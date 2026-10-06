"""Authorized security-awareness campaign tooling.

This subsystem builds the *legitimate* side of a "phishing" exercise: it helps
an organization train its own staff to recognize real scams. It is **not** an
attack tool and is deliberately built so it cannot become one:

* It never captures or transmits credentials. The landing page it renders is
  purely educational — there is no login form, no password field, no POST of
  secrets anywhere.
* It never sends e-mail. It can render a training e-mail *template* (text), but
  there is no SMTP, no transport, no "send" function in this module.
* It refuses to produce campaign artifacts unless an engagement is backed by a
  recorded authorization (who approved it, and when) and a recipient allowlist.
  Any recipient outside the allowlist aborts generation.

Metrics are aggregate and non-punitive: :func:`tally_clicks` reports how many
tokens were seen and the click-through rate, never a per-person score meant to
single out or discipline an individual.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from dataclasses import dataclass, field
from datetime import date
from html import escape
from urllib.parse import quote

from ..core.i18n import L, Lf


class AwarenessError(Exception):
    """Base class for all awareness-subsystem errors."""


class AuthorizationError(AwarenessError):
    """Raised when a campaign lacks recorded authorization to proceed."""


class AllowlistError(AwarenessError):
    """Raised when a recipient falls outside the configured allowlist."""


def _normalize_email(value: str) -> str:
    return value.strip().lower()


def _domain_of(email: str) -> str:
    _, _, domain = _normalize_email(email).partition("@")
    return domain


@dataclass(frozen=True)
class Authorization:
    """Recorded sign-off for a training campaign.

    Both fields are mandatory. An empty ``authorized_by`` or a missing
    ``authorized_on`` means the campaign is not authorized and generation is
    refused.
    """

    authorized_by: str
    authorized_on: date

    def __post_init__(self) -> None:
        if not self.authorized_by or not self.authorized_by.strip():
            raise AuthorizationError(
                L(
                    "a campanha exige 'authorized_by' (nome da pessoa que "
                    "aprovou este exercício de conscientização)",
                    "campaign requires 'authorized_by' (name of the person who "
                    "approved this awareness exercise)",
                )
            )
        if not isinstance(self.authorized_on, date):
            raise AuthorizationError(
                L(
                    "a campanha exige 'authorized_on' como data "
                    "(quando o exercício foi aprovado)",
                    "campaign requires 'authorized_on' as a date "
                    "(when the exercise was approved)",
                )
            )

    @classmethod
    def create(cls, authorized_by: str | None, authorized_on: str | date | None) -> "Authorization":
        """Build an :class:`Authorization`, parsing an ISO date string if given."""
        if authorized_by is None or not str(authorized_by).strip():
            raise AuthorizationError(
                L(
                    "autorização ausente: forneça --authorized-by (quem aprovou "
                    "este exercício de conscientização)",
                    "missing authorization: provide --authorized-by (who approved "
                    "this awareness exercise)",
                )
            )
        if authorized_on is None or (isinstance(authorized_on, str) and not authorized_on.strip()):
            raise AuthorizationError(
                L(
                    "autorização ausente: forneça --authorized-on (a data de "
                    "aprovação, ex.: 2026-10-05)",
                    "missing authorization: provide --authorized-on (the approval "
                    "date, e.g. 2026-10-05)",
                )
            )
        if isinstance(authorized_on, date):
            parsed = authorized_on
        else:
            try:
                parsed = date.fromisoformat(authorized_on.strip())
            except ValueError as exc:
                raise AuthorizationError(
                    Lf(
                        "data de autorização inválida {value!r}: use o formato "
                        "ISO AAAA-MM-DD",
                        "invalid authorization date {value!r}: use ISO "
                        "format YYYY-MM-DD",
                        value=authorized_on,
                    )
                ) from exc
        return cls(authorized_by=authorized_by.strip(), authorized_on=parsed)


@dataclass(frozen=True)
class Allowlist:
    """Who a campaign may target.

    An allowlist entry is either a full e-mail address (``alice@corp.com``) or a
    bare domain (``corp.com``). Matching is case-insensitive. An empty allowlist
    is rejected — a campaign with no boundary is indistinguishable from an
    unbounded blast and is refused.
    """

    domains: frozenset[str] = field(default_factory=frozenset)
    emails: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.domains and not self.emails:
            raise AllowlistError(
                L(
                    "allowlist vazia: uma campanha deve declarar ao menos um "
                    "domínio ou endereço de e-mail permitido",
                    "empty allowlist: a campaign must declare at least one "
                    "permitted domain or e-mail address",
                )
            )

    @classmethod
    def from_entries(cls, entries) -> "Allowlist":
        """Split an iterable of entries into e-mail and domain allowlists."""
        if entries is None:
            raise AllowlistError(
                L(
                    "allowlist ausente: forneça o(s) domínio(s) e/ou e-mail(s) que "
                    "a campanha está autorizada a atingir",
                    "missing allowlist: provide the domain(s) and/or e-mail(s) a "
                    "campaign is permitted to target",
                )
            )
        domains: set[str] = set()
        emails: set[str] = set()
        for raw in entries:
            if raw is None:
                continue
            item = str(raw).strip().lower()
            if not item:
                continue
            if "@" in item:
                emails.add(item)
            else:
                domains.add(item.lstrip("@"))
        return cls(domains=frozenset(domains), emails=frozenset(emails))

    def permits(self, recipient: str) -> bool:
        """True iff ``recipient`` is covered by an e-mail or domain entry."""
        addr = _normalize_email(recipient)
        if addr in self.emails:
            return True
        return _domain_of(addr) in self.domains

    def validate(self, recipients) -> list[str]:
        """Return the normalized recipient list, or raise on the first that is
        outside the allowlist.

        This is the hard gate: generation calls it and will not emit any
        artifact if a single recipient is out of bounds.
        """
        normalized: list[str] = []
        rejected: list[str] = []
        for r in recipients:
            addr = _normalize_email(str(r))
            if not addr:
                continue
            if self.permits(addr):
                normalized.append(addr)
            else:
                rejected.append(addr)
        if rejected:
            raise AllowlistError(
                L(
                    "destinatário(s) fora da allowlist — recusando a geração de "
                    "artefatos da campanha: ",
                    "recipient(s) outside the allowlist — refusing to generate "
                    "campaign artifacts: ",
                )
                + ", ".join(sorted(set(rejected)))
            )
        if not normalized:
            raise AllowlistError(L("nenhum destinatário fornecido para a campanha", "no recipients provided for the campaign"))
        return normalized


@dataclass(frozen=True)
class RecipientToken:
    """A single recipient paired with their unique tracking token and link."""

    recipient: str
    token: str
    tracking_url: str


@dataclass
class Campaign:
    """An authorized, allowlist-bounded awareness exercise.

    Construction enforces the ethical gate: a :class:`Campaign` cannot exist
    without an :class:`Authorization` and a non-empty :class:`Allowlist`, and
    every recipient is validated against the allowlist up front.
    """

    name: str
    authorization: Authorization
    allowlist: Allowlist
    base_url: str
    recipients: list[str]
    tokens: list[RecipientToken] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.authorization, Authorization):
            raise AuthorizationError(L("a campanha exige uma Authorization válida", "campaign requires a valid Authorization"))
        if not isinstance(self.allowlist, Allowlist):
            raise AllowlistError(L("a campanha exige uma Allowlist válida", "campaign requires a valid Allowlist"))
        if not self.base_url or not self.base_url.strip():
            raise AwarenessError(
                L(
                    "base_url é obrigatória (a URL hospedada pelo operador da "
                    "página educativa de destino)",
                    "base_url is required (the operator-hosted URL of the "
                    "educational landing page)",
                )
            )
        self.base_url = self.base_url.strip()
        # Hard gate: validate recipients against the allowlist BEFORE anything
        # is generated. Raises AllowlistError on the first out-of-bounds entry.
        self.recipients = self.allowlist.validate(self.recipients)
        if not self.tokens:
            self.tokens = self._mint_tokens()

    def _mint_tokens(self) -> list[RecipientToken]:
        out: list[RecipientToken] = []
        for recipient in self.recipients:
            token = uuid.uuid4().hex
            out.append(
                RecipientToken(
                    recipient=recipient,
                    token=token,
                    tracking_url=build_tracking_url(self.base_url, token),
                )
            )
        return out

    def token_values(self) -> list[str]:
        return [t.token for t in self.tokens]

    def tokens_to_csv(self) -> str:
        """Serialize the recipient/token/link map as CSV."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["recipient", "token", "tracking_url"])
        for t in self.tokens:
            writer.writerow([t.recipient, t.token, t.tracking_url])
        return buf.getvalue()

    def tokens_to_json(self) -> str:
        """Serialize the campaign metadata and recipient/token map as JSON."""
        payload = {
            "campaign": self.name,
            "authorized_by": self.authorization.authorized_by,
            "authorized_on": self.authorization.authorized_on.isoformat(),
            "base_url": self.base_url,
            "recipients": [
                {
                    "recipient": t.recipient,
                    "token": t.token,
                    "tracking_url": t.tracking_url,
                }
                for t in self.tokens
            ],
        }
        return json.dumps(payload, indent=2)


def build_tracking_url(base_url: str, token: str) -> str:
    """Compose ``{base_url}?t={token}``, preserving an existing query string."""
    sep = "&" if "?" in base_url else "?"
    return f"{base_url}{sep}t={quote(token, safe='')}"


def tally_clicks(tokens, click_log) -> dict:
    """Aggregate, non-punitive click metrics.

    Given the set of ``tokens`` issued for a campaign and a ``click_log`` (an
    iterable of tokens observed, e.g. from the operator's own web logs), return
    only aggregate figures:

    * ``sent`` — how many unique, valid tokens were issued
    * ``clicked`` — how many distinct issued tokens appear in the log
    * ``click_rate`` — ``clicked / sent`` (0.0 when nothing was sent)

    Tokens in the log that were never issued are ignored (``unknown_hits`` is
    reported as a count only, for data-hygiene, never tied to a person).
    No individual recipient is named, scored, or ranked.
    """
    issued = {t for t in tokens if t}
    seen = [t for t in click_log if t]
    seen_set = set(seen)

    clicked = len(issued & seen_set)
    sent = len(issued)
    unknown = len(seen_set - issued)
    rate = (clicked / sent) if sent else 0.0

    return {
        "sent": sent,
        "clicked": clicked,
        "not_clicked": sent - clicked,
        "click_rate": round(rate, 4),
        "unknown_hits": unknown,
    }


def render_landing_page(
    *,
    campaign_name: str | None = None,
    authorized_by: str | None = None,
    authorized_on: str | date | None = None,
    org_contact: str | None = None,
) -> str:
    """Return a self-contained, educational landing-page HTML.

    This page is shown *after* a trainee clicks a simulated link. It contains
    **no** input fields of any kind — no login form, no password field, no
    credential POST. Its sole purpose is to explain that the message was a
    sanctioned awareness test and to teach how to spot real phishing.
    """
    name = escape(campaign_name or L("Exercício de Conscientização em Segurança", "Security Awareness Exercise"))
    by = escape(authorized_by) if authorized_by else None
    on = authorized_on.isoformat() if isinstance(authorized_on, date) else (
        escape(str(authorized_on)) if authorized_on else None
    )
    contact = escape(org_contact) if org_contact else L("sua equipe de segurança", "your security team")

    auth_line = ""
    if by and on:
        auth_line = (
            f'<p class="auth">'
            + Lf(
                "Exercício de conscientização autorizado · aprovado por "
                "<strong>{by}</strong> em <strong>{on}</strong>.",
                "Authorized awareness exercise · approved by "
                "<strong>{by}</strong> on <strong>{on}</strong>.",
                by=by, on=on,
            )
            + "</p>"
        )

    return f"""<!doctype html>
<html lang="{L("pt-BR", "en")}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{name} — {L("Treinamento de Conscientização", "Awareness Training")}</title>
<style>
  :root {{
    --bg: #0b1020; --panel: #121a30; --ink: #e7ecf5; --muted: #9fb0cc;
    --accent: #5ad1a8; --warn: #ffd166; --line: #233150;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--ink);
    font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    display: flex; min-height: 100vh; align-items: center; justify-content: center;
    padding: 24px;
  }}
  .card {{
    width: 100%; max-width: 680px; background: var(--panel);
    border: 1px solid var(--line); border-radius: 16px; padding: 32px 36px;
    box-shadow: 0 20px 60px rgba(0,0,0,.45);
  }}
  .badge {{
    display: inline-block; font-size: 13px; letter-spacing: .08em;
    text-transform: uppercase; color: var(--bg); background: var(--accent);
    padding: 4px 12px; border-radius: 999px; font-weight: 700;
  }}
  h1 {{ font-size: 28px; margin: 18px 0 8px; }}
  .lead {{ color: var(--muted); font-size: 18px; margin: 0 0 20px; }}
  .auth {{
    font-size: 14px; color: var(--muted); border-left: 3px solid var(--accent);
    padding-left: 12px; margin: 0 0 24px;
  }}
  h2 {{ font-size: 18px; margin: 28px 0 10px; color: var(--accent); }}
  ul {{ margin: 0 0 8px; padding-left: 20px; }}
  li {{ margin: 6px 0; }}
  .flag {{ color: var(--warn); font-weight: 600; }}
  .foot {{
    margin-top: 28px; padding-top: 18px; border-top: 1px solid var(--line);
    color: var(--muted); font-size: 14px;
  }}
</style>
</head>
<body>
  <main class="card">
    <span class="badge">{L("Treinamento de Conscientização", "Awareness Training")}</span>
    <h1>{L("Isto foi um teste de conscientização em segurança.", "This was a security awareness test.")}</h1>
    <p class="lead">
      {Lf(
        "Você seguiu um link de uma mensagem de phishing simulada enviada por "
        "{contact}. Nenhum dano foi causado e <strong>nada sobre você foi "
        "registrado além de um clique anônimo</strong>. Este exercício existe "
        "para ajudar você — não para pegá-lo de surpresa.",
        "You followed a link from a simulated phishing message sent by {contact}. "
        "No harm was done and <strong>nothing about you was recorded beyond an "
        "anonymous click</strong>. This exercise is here to help you — not to "
        "catch you out.",
        contact=contact,
      )}
    </p>
    {auth_line}

    <h2>{L("Como identificar a próxima", "How to spot the next one")}</h2>
    <ul>
      <li><span class="flag">{L("Urgência inesperada.", "Unexpected urgency.")}</span> {L(
        "\"Aja agora ou sua conta será bloqueada\" é uma pressão criada para "
        "impedir você de pensar.",
        "\"Act now or your account will be locked\" is pressure designed to stop "
        "you thinking.")}</li>
      <li><span class="flag">{L("Remetente e links incompatíveis.", "Mismatched sender &amp; links.")}</span> {L(
        "Passe o mouse sobre os links antes de clicar; verifique o domínio real, "
        "não o texto exibido.",
        "Hover over links before clicking; check the real domain, not the display "
        "text.")}</li>
      <li><span class="flag">{L("Pedidos de credenciais.", "Requests for credentials.")}</span> {L(
        "Uma equipe de TI legítima nunca pedirá sua senha por e-mail ou em uma "
        "página vinculada.",
        "Legitimate IT will never ask for your password by e-mail or on a linked "
        "page.")}</li>
      <li><span class="flag">{L("Saudações ou gramática estranhas.", "Odd greetings or grammar.")}</span> {L(
        "Um genérico \"Prezado usuário\" e pequenos deslizes de linguagem são "
        "sinais comuns.",
        "Generic \"Dear user\" and small language slips are common tells.")}</li>
      <li><span class="flag">{L("Anexos inesperados.", "Unexpected attachments.")}</span> {L(
        "Não abra arquivos que você não esperava, mesmo de nomes conhecidos.",
        "Do not open files you were not expecting, even from known names.")}</li>
    </ul>

    <h2>{L("O que fazer ao suspeitar de phishing", "What to do when you suspect phishing")}</h2>
    <ul>
      <li>{L("Não clique, não responda e não insira nenhuma informação.", "Do not click, reply, or enter any information.")}</li>
      <li>{Lf("Reporte para {contact} usando seu canal normal de denúncia.", "Report it to {contact} using your normal reporting channel.", contact=contact)}</li>
      <li>{L("Na dúvida, verifique por um canal em que você já confia.", "When in doubt, verify through a channel you already trust.")}</li>
    </ul>

    <p class="foot">
      {L(
        "Reportar uma mensagem suspeita é sempre a atitude certa — você nunca "
        "será penalizado por isso. Obrigado por ajudar a manter todos seguros.",
        "Reporting a suspicious message is always the right call — you will never "
        "be penalized for it. Thank you for helping keep everyone safe.",
      )}
    </p>
  </main>
</body>
</html>
"""


def render_email_template(
    *,
    campaign_name: str | None = None,
    tracking_url: str = "{{TRACKING_URL}}",
    sender_pretext: str | None = None,
    authorized_by: str | None = None,
    authorized_on: str | date | None = None,
) -> str:
    """Return a plain-text training e-mail *template*.

    This is text only. There is deliberately **no** function anywhere in this
    subsystem that sends it. The template carries an explicit footer marking it
    as an authorized simulation so that anyone reviewing the message (or the
    recipient afterwards) can see it was a sanctioned training exercise.

    ``tracking_url`` defaults to a ``{{TRACKING_URL}}`` placeholder so a single
    rendered template can be reused across recipients by substituting each
    recipient's own link from the generated token map.
    """
    on = authorized_on.isoformat() if isinstance(authorized_on, date) else (
        str(authorized_on) if authorized_on else "N/A"
    )
    campaign_name = campaign_name or L("Exercício de Conscientização em Segurança", "Security Awareness Exercise")
    sender_pretext = sender_pretext or L("Central de Atendimento de TI", "IT Service Desk")
    by = authorized_by or L("a equipe de segurança da organização", "the organization's security team")

    return f"""{L("Assunto", "Subject")}: {L("Ação necessária: verifique o acesso à sua conta", "Action required: verify your account access")}

{L("De", "From")}: {sender_pretext}

{L("Olá,", "Hello,")}

{Lf(
    "Estamos realizando uma revisão de rotina do acesso às contas. Por favor, "
    "revise seus dados no link abaixo assim que possível:",
    "We are carrying out a routine review of account access. Please review your "
    "details at the link below at your earliest convenience:",
)}

    {tracking_url}

{L("Em caso de dúvidas, entre em contato com a central de atendimento.", "If you have any questions, contact the service desk.")}

{L("Obrigado,", "Thank you,")}
{sender_pretext}

----------------------------------------------------------------------
{L("AVISO DE SIMULAÇÃO — TREINAMENTO DE CONSCIENTIZAÇÃO EM SEGURANÇA", "SIMULATION NOTICE — SECURITY AWARENESS TRAINING")}
{Lf(
    "Esta mensagem é um e-mail de phishing SIMULADO, parte do exercício "
    "autorizado de conscientização \"{campaign}\". Ela não foi enviada por uma "
    "central de atendimento real e não pede nada verdadeiro. Autorizado por: "
    "{by}; data de aprovação: {on}. O link leva apenas a uma página educativa. "
    "Nenhuma credencial é coletada.",
    "This message is a SIMULATED phishing e-mail, part of the authorized "
    "\"{campaign}\" awareness exercise. It was not sent by a real service "
    "desk and asks for nothing real. Authorized by: {by}; approval date: {on}. "
    "The link leads only to an educational page. No credentials are collected.",
    campaign=campaign_name, by=by, on=on,
)}
----------------------------------------------------------------------
"""
