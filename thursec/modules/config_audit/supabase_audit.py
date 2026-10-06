"""Supabase posture audit — self-assessment of *your own* project — pure stdlib.

SCOPE / BOUNDARY (read this first)
----------------------------------
This module is for auditing the security posture of a Supabase project **you
own**, using **your own** credentials. It is strictly PASSIVE: it only *reads*
configuration and metadata (the PostgREST schema, a one-row probe per table,
the storage bucket list, HTTP response headers) that the supplied key is already
entitled to see. It performs no brute force, no privilege escalation, and never
touches a project it was not handed credentials for. Point it at someone else's
project and it simply has no valid key to use.

Because it reaches your project over the network with a credential *you* provide
(rather than attacking an arbitrary target), it is modelled as PASSIVE and does
not go through the scope gate — but it still requires you to own the project.

What it checks
--------------
1. Anonymous data exposure: with the ``anon`` key, discover tables from the
   PostgREST OpenAPI schema and probe each with ``SELECT ... limit 1``. Tables
   that return rows to the anonymous role mean RLS is disabled or a policy is
   too permissive — reported HIGH.
2. service_role key misuse: the ``service_role`` key bypasses RLS entirely and
   must live only on trusted servers. If you tell the module it is used in a
   browser/client (``service_key_in_client: true``) that is reported CRITICAL;
   otherwise the risk is documented as INFO.
3. Public storage buckets: list buckets and flag the public ones (MEDIUM).
4. Basic HTTP posture of the project URL (missing HSTS, Server banner, etc.).

Credential redaction
---------------------
API keys are secrets. No finding ever embeds a full key — keys are masked to a
short head/tail fingerprint (see :func:`_mask`).
"""

from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

from ...core.context import RunContext
from ...core.finding import Finding, Severity
from ...core.i18n import L, Lf
from ...core.module import Category, Intensity, Module

_USER_AGENT = "ThurSec/0.1"
_TIMEOUT = 15
# Cap how many tables we probe so a huge schema can't blow up the run.
_MAX_TABLES = 40
# How many exposed table names to show inline in evidence.
_EVIDENCE_LIMIT = 20


@dataclass(slots=True)
class HttpResponse:
    """Minimal response shape so the HTTP layer is trivial to fake in tests."""

    status: int
    headers: dict[str, str]
    body: str

    def json(self) -> object:
        return json.loads(self.body) if self.body else None


class SupabaseAudit(Module):
    id = "config_audit.supabase"
    category = Category.CONFIG_AUDIT
    intensity = Intensity.PASSIVE

    @property
    def name(self) -> str:
        return L("Auditoria de postura do Supabase", "Supabase posture audit")

    @property
    def description(self) -> str:
        return L(
            "Audita a postura de segurança do SEU PRÓPRIO projeto Supabase usando "
            "as SUAS PRÓPRIAS credenciais (chave anon e/ou service_role). Passiva, "
            "somente-leitura: verifica exposição anônima de tabelas (RLS), uso "
            "indevido da chave service_role e buckets de armazenamento públicos. "
            "Nunca execute contra um projeto que você não possui.",
            "Audit the security posture of YOUR OWN Supabase project using YOUR OWN "
            "credentials (anon and/or service_role key). Passive, read-only: checks "
            "anonymous table exposure (RLS), service_role key misuse, and public "
            "storage buckets. Never run against a project you do not own.",
        )

    async def run(self, ctx: RunContext) -> list[Finding]:
        base = _base_url(ctx.options.get("supabase_url") or ctx.target)
        anon_key = ctx.options.get("anon_key") or os.environ.get("SUPABASE_ANON_KEY")
        service_key = ctx.options.get("service_role_key") or os.environ.get(
            "SUPABASE_SERVICE_ROLE_KEY"
        )
        key_in_client = bool(ctx.options.get("service_key_in_client", False))

        if not base:
            return [
                ctx.finding(
                    self.id,
                    L("Nenhuma URL de projeto Supabase fornecida", "No Supabase project URL provided"),
                    Severity.INFO,
                    description=L(
                        "Forneça a URL do seu próprio projeto Supabase pela opção "
                        "'supabase_url' ou como alvo "
                        "(ex.: https://<ref>.supabase.co).",
                        "Supply the URL of your own Supabase project via the "
                        "'supabase_url' option or as the target "
                        "(e.g. https://<ref>.supabase.co).",
                    ),
                    recommendation=L("Forneça a URL do seu projeto e uma chave de API.", "Provide your project URL and an API key."),
                )
            ]

        if not anon_key and not service_key:
            return [
                ctx.finding(
                    self.id,
                    L("Nenhuma credencial do Supabase fornecida", "No Supabase credentials provided"),
                    Severity.INFO,
                    description=L(
                        "Esta auditoria lê a configuração do SEU PRÓPRIO projeto e "
                        "precisa de uma credencial que você possui. Forneça 'anon_key' "
                        "e/ou 'service_role_key' (opção ou env SUPABASE_ANON_KEY / "
                        "SUPABASE_SERVICE_ROLE_KEY).",
                        "This audit reads your OWN project's configuration and "
                        "needs a credential you own. Provide 'anon_key' and/or "
                        "'service_role_key' (option or env SUPABASE_ANON_KEY / "
                        "SUPABASE_SERVICE_ROLE_KEY).",
                    ),
                    recommendation=L("Forneça a chave anon e/ou service_role.", "Provide the anon and/or service_role key."),
                )
            ]

        findings: list[Finding] = []
        findings.extend(self._check_service_key(ctx, service_key, key_in_client))
        if anon_key:
            findings.extend(await self._check_anon_exposure(ctx, base, anon_key))
        findings.extend(
            await self._check_storage_buckets(ctx, base, service_key, anon_key)
        )
        findings.extend(await self._check_http_posture(ctx, base))
        return findings

    # --- check 1: anonymous data exposure ----------------------------------
    async def _check_anon_exposure(
        self, ctx: RunContext, base: str, anon_key: str
    ) -> list[Finding]:
        try:
            spec = await asyncio.to_thread(
                self._request, "GET", f"{base}/rest/v1/", anon_key
            )
        except Exception as e:
            return [self._error_finding(ctx, L("a consulta anônima do schema REST", "anonymous REST schema lookup"), anon_key, e)]

        if spec.status in (401, 403):
            return [
                ctx.finding(
                    self.id,
                    L("Acesso anônimo à API REST é rejeitado", "Anonymous access to REST API is rejected"),
                    Severity.INFO,
                    description=Lf(
                        "A chave anon não conseguiu ler o schema do PostgREST "
                        "(HTTP {status}); a API não é navegável anonimamente.",
                        "The anon key could not read the PostgREST schema "
                        "(HTTP {status}); the API is not anonymously browsable.",
                        status=spec.status,
                    ),
                    evidence=f"GET /rest/v1/ -> {spec.status} (anon {_mask(anon_key)})",
                )
            ]

        tables = _tables_from_openapi(spec.body)
        if not tables:
            return [
                ctx.finding(
                    self.id,
                    L("Nenhuma tabela detectável pelo schema REST anônimo", "No tables discoverable via anonymous REST schema"),
                    Severity.INFO,
                    description=L(
                        "O schema anônimo do PostgREST não expôs nenhuma definição "
                        "de tabela para sondar.",
                        "The anonymous PostgREST schema exposed no table "
                        "definitions to probe.",
                    ),
                    evidence=f"GET /rest/v1/ -> {spec.status} (anon {_mask(anon_key)})",
                )
            ]

        exposed: list[str] = []
        probed = 0
        for table in tables[:_MAX_TABLES]:
            probed += 1
            path = f"{base}/rest/v1/{table}?select=*&limit=1"
            try:
                resp = await asyncio.to_thread(self._request, "GET", path, anon_key)
            except Exception:
                continue
            if resp.status == 200 and _has_rows(resp.body):
                exposed.append(table)

        findings: list[Finding] = []
        if exposed:
            shown = exposed[:_EVIDENCE_LIMIT]
            evidence = "\n".join(shown)
            if len(exposed) > len(shown):
                evidence += f"\n... (+{len(exposed) - len(shown)} more)"
            findings.append(
                ctx.finding(
                    self.id,
                    Lf("A role anônima consegue ler dados de {n} tabela(s)", "Anonymous role can read data from {n} table(s)", n=len(exposed)),
                    Severity.HIGH,
                    description=L(
                        "A chave anônima (anon) retornou linhas reais destas "
                        "tabelas, o que significa que o Row Level Security está "
                        "desativado ou uma política SELECT é permissiva demais. "
                        "Qualquer pessoa com a chave anon pública pode ler esses dados.",
                        "The anonymous (anon) key returned actual rows from these "
                        "tables, which means Row Level Security is disabled or a "
                        "SELECT policy is too permissive. Anyone with the public "
                        "anon key can read this data.",
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Enable RLS on every table in exposed schemas and write "
                        "explicit policies. Grant anon access only to data that is "
                        "intentionally public."
                    ),
                    references=[
                        "https://supabase.com/docs/guides/database/postgres/row-level-security"
                    ],
                    metadata={
                        "exposed_tables": exposed,
                        "tables_probed": probed,
                        "anon_key": _mask(anon_key),
                    },
                )
            )
        else:
            findings.append(
                ctx.finding(
                    self.id,
                    L("Nenhuma exposição anônima de dados detectada", "No anonymous data exposure detected"),
                    Severity.INFO,
                    description=Lf(
                        "Sondou {probed} tabela(s) com a chave anon; nenhuma "
                        "retornou linhas, consistente com RLS aplicado.",
                        "Probed {probed} table(s) with the anon key; none returned "
                        "rows, consistent with RLS being enforced.",
                        probed=probed,
                    ),
                    evidence=f"tables_probed={probed} (anon {_mask(anon_key)})",
                    metadata={"tables_probed": probed, "anon_key": _mask(anon_key)},
                )
            )
        return findings

    # --- check 2: service_role key misuse ----------------------------------
    def _check_service_key(
        self, ctx: RunContext, service_key: str | None, key_in_client: bool
    ) -> list[Finding]:
        if not service_key:
            return []
        role = _jwt_role(service_key)
        findings: list[Finding] = []
        if key_in_client:
            findings.append(
                ctx.finding(
                    self.id,
                    L("a chave service_role é usada em código do lado do cliente (client-side)", "service_role key is used in client-side code"),
                    Severity.CRITICAL,
                    description=L(
                        "A chave service_role ignora completamente o Row Level "
                        "Security. Se ela for distribuída para navegadores / apps "
                        "móveis, qualquer um pode extraí-la e obter acesso total de "
                        "leitura/escrita ao banco de dados.",
                        "The service_role key bypasses Row Level Security entirely. "
                        "If it is shipped to browsers / mobile apps, anyone can "
                        "extract it and gain full read/write access to the database.",
                    ),
                    evidence=f"service_role key {_mask(service_key)} (role={role})",
                    recommendation=L(
                        "Remova a chave service_role de todo o código do cliente "
                        "imediatamente, rotacione-a no painel do Supabase e use a "
                        "chave anon (com RLS) nos clientes. Mantenha a service_role "
                        "apenas em servidores confiáveis / edge functions.",
                        "Remove the service_role key from all client code "
                        "immediately, rotate it in the Supabase dashboard, and use "
                        "the anon key (with RLS) in clients. Keep service_role only "
                        "on trusted servers / edge functions.",
                    ),
                    references=[
                        "https://supabase.com/docs/guides/api/api-keys"
                    ],
                    metadata={"service_role_key": _mask(service_key), "role": role},
                )
            )
        else:
            findings.append(
                ctx.finding(
                    self.id,
                    L("chave service_role fornecida — garanta que ela permaneça no servidor (server-side)", "service_role key provided — ensure it stays server-side"),
                    Severity.INFO,
                    description=L(
                        "Uma chave service_role foi fornecida para esta auditoria. "
                        "Ela ignora o RLS e nunca deve chegar a um navegador, app "
                        "móvel ou repositório público. Defina "
                        "'service_key_in_client: true' se ela for usada no cliente "
                        "para escalar este achado.",
                        "A service_role key was supplied for this audit. It bypasses "
                        "RLS and must never reach a browser, mobile app, or public "
                        "repository. Set 'service_key_in_client: true' if it is used "
                        "client-side to escalate this finding.",
                    ),
                    evidence=f"service_role key {_mask(service_key)} (role={role})",
                    recommendation=L(
                        "Armazene a chave service_role apenas em ambientes de "
                        "servidor confiáveis e rotacione-a se ela já tiver sido exposta.",
                        "Store the service_role key only in trusted server "
                        "environments and rotate it if it has ever been exposed.",
                    ),
                    metadata={"service_role_key": _mask(service_key), "role": role},
                )
            )
        return findings

    # --- check 3: public storage buckets -----------------------------------
    async def _check_storage_buckets(
        self,
        ctx: RunContext,
        base: str,
        service_key: str | None,
        anon_key: str | None,
    ) -> list[Finding]:
        key = service_key or anon_key
        if not key:
            return []
        try:
            resp = await asyncio.to_thread(
                self._request, "GET", f"{base}/storage/v1/bucket", key
            )
        except Exception as e:
            return [self._error_finding(ctx, L("a listagem de buckets de armazenamento", "storage bucket listing"), key, e)]

        if resp.status in (401, 403):
            return [
                ctx.finding(
                    self.id,
                    L("Listagem de buckets de armazenamento não permitida para esta chave", "Storage bucket listing not permitted for this key"),
                    Severity.INFO,
                    description=Lf(
                        "A listagem de buckets retornou HTTP {status}; a chave "
                        "fornecida pode não ter acesso ao armazenamento. Use a chave "
                        "service_role para enumerar os buckets.",
                        "Listing buckets returned HTTP {status}; the supplied "
                        "key may lack storage access. Use the service_role key to "
                        "enumerate buckets.",
                        status=resp.status,
                    ),
                    evidence=f"GET /storage/v1/bucket -> {resp.status} ({_mask(key)})",
                )
            ]

        try:
            data = resp.json()
        except Exception:
            data = None
        if not isinstance(data, list):
            return [
                ctx.finding(
                    self.id,
                    L("Não foi possível interpretar a listagem de buckets de armazenamento", "Could not parse storage bucket listing"),
                    Severity.LOW,
                    evidence=f"GET /storage/v1/bucket -> {resp.status} ({_mask(key)})",
                )
            ]

        public = [
            str(b.get("name") or b.get("id"))
            for b in data
            if isinstance(b, dict) and b.get("public") is True
        ]
        if not public:
            return [
                ctx.finding(
                    self.id,
                    L("Nenhum bucket de armazenamento público", "No public storage buckets"),
                    Severity.INFO,
                    description=Lf("Todos os {n} bucket(s) de armazenamento são privados.", "All {n} storage bucket(s) are private.", n=len(data)),
                    evidence=f"buckets={len(data)} ({_mask(key)})",
                    metadata={"bucket_count": len(data)},
                )
            ]
        return [
            ctx.finding(
                self.id,
                Lf("{n} bucket(s) de armazenamento público(s)", "{n} public storage bucket(s)", n=len(public)),
                Severity.MEDIUM,
                description=L(
                    "Estes buckets de armazenamento estão marcados como públicos, "
                    "então seus objetos podem ser lidos por qualquer um que tenha a "
                    "URL. Confirme que eles contêm apenas dados destinados a serem "
                    "públicos.",
                    "These storage buckets are marked public, so their objects are "
                    "readable by anyone with the URL. Confirm they hold only data "
                    "meant to be public.",
                ),
                evidence="\n".join(public),
                recommendation=L(
                    "Torne os buckets privados e sirva os arquivos via URLs "
                    "assinadas, a menos que o conteúdo seja genuinamente público. "
                    "Aplique políticas de RLS de armazenamento.",
                    "Make buckets private and serve files via signed URLs unless the "
                    "content is genuinely public. Apply storage RLS policies.",
                ),
                references=["https://supabase.com/docs/guides/storage/security/access-control"],
                metadata={"public_buckets": public, "bucket_count": len(data)},
            )
        ]

    # --- check 4: basic HTTP posture ---------------------------------------
    async def _check_http_posture(self, ctx: RunContext, base: str) -> list[Finding]:
        try:
            resp = await asyncio.to_thread(self._request, "GET", f"{base}/", None)
        except Exception as e:
            return [
                ctx.finding(
                    self.id,
                    L("Não foi possível obter os cabeçalhos da URL do projeto", "Could not fetch project URL headers"),
                    Severity.LOW,
                    evidence=f"{type(e).__name__}: {e}",
                )
            ]
        headers = {k.lower(): v for k, v in resp.headers.items()}
        findings: list[Finding] = []
        if "strict-transport-security" not in headers:
            findings.append(
                ctx.finding(
                    self.id,
                    L("URL do projeto sem o cabeçalho Strict-Transport-Security", "Project URL missing Strict-Transport-Security header"),
                    Severity.LOW,
                    description=L(
                        "O endpoint do projeto Supabase não retornou um cabeçalho HSTS.",
                        "The Supabase project endpoint did not return an HSTS header.",
                    ),
                    recommendation=L("Garanta que o HTTPS seja aplicado em todo o tráfego da API.", "Ensure HTTPS is enforced for all API traffic."),
                )
            )
        return findings

    # --- helpers -----------------------------------------------------------
    def _error_finding(
        self, ctx: RunContext, what: str, key: str, exc: Exception
    ) -> Finding:
        return ctx.finding(
            self.id,
            Lf("Não foi possível completar {what}", "Could not complete {what}", what=what),
            Severity.LOW,
            description=Lf(
                "{what} não foi concluído. Isso pode indicar uma credencial "
                "inválida, um problema de rede, ou que o endpoint está inacessível.",
                "The {what} did not complete. This can mean an invalid credential, "
                "network issue, or that the endpoint is unreachable.",
                what=what,
            ),
            evidence=f"{type(exc).__name__}: {exc} ({_mask(key)})",
            recommendation=L("Verifique a URL do projeto e se a chave é válida.", "Verify the project URL and that the key is valid."),
        )

    # --- isolable HTTP layer (monkeypatched in tests) ----------------------
    def _request(
        self, method: str, url: str, apikey: str | None, body: bytes | None = None
    ) -> HttpResponse:
        """Perform one blocking HTTP request against the user's own project.

        Isolated so tests can replace it with canned responses — no network.
        """
        headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
        if apikey:
            headers["apikey"] = apikey
            headers["Authorization"] = f"Bearer {apikey}"
        req = urllib.request.Request(url, method=method, headers=headers, data=body)
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return HttpResponse(resp.status, dict(resp.getheaders()), raw)
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace") if e.fp else ""
            return HttpResponse(e.code, dict(e.headers or {}), raw)


# --- module-level helpers --------------------------------------------------
def _base_url(target: str | None) -> str:
    """Normalise a project URL to scheme://host with no trailing slash."""
    if not target:
        return ""
    t = target.strip()
    if "://" not in t:
        t = "https://" + t
    from urllib.parse import urlparse

    p = urlparse(t)
    if not p.hostname:
        return ""
    scheme = p.scheme or "https"
    netloc = p.hostname + (f":{p.port}" if p.port else "")
    return f"{scheme}://{netloc}"


def _mask(key: str | None) -> str:
    """Redact a secret to a short head/tail fingerprint. Never leak the key."""
    if not key:
        return "<none>"
    k = str(key)
    if len(k) <= 12:
        return "****"
    return f"{k[:4]}…{k[-4:]} (len={len(k)})"


def _jwt_role(token: str) -> str:
    """Best-effort read of the 'role' claim from a JWT. No signature check."""
    try:
        import base64

        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return str(data.get("role", "unknown"))
    except Exception:
        return "unknown"


def _tables_from_openapi(body: str) -> list[str]:
    """Extract table/view names from a PostgREST OpenAPI (Swagger) document."""
    try:
        doc = json.loads(body)
    except Exception:
        return []
    if not isinstance(doc, dict):
        return []
    names: set[str] = set()
    definitions = doc.get("definitions")
    if isinstance(definitions, dict):
        names.update(k for k in definitions if isinstance(k, str))
    paths = doc.get("paths")
    if isinstance(paths, dict):
        for p in paths:
            if isinstance(p, str) and p.startswith("/") and p != "/":
                seg = p.lstrip("/").split("/", 1)[0]
                if seg and not seg.startswith("rpc"):
                    names.add(seg)
    return sorted(names)


def _has_rows(body: str) -> bool:
    """True if a PostgREST response body is a non-empty JSON array."""
    try:
        data = json.loads(body)
    except Exception:
        return False
    return isinstance(data, list) and len(data) > 0
