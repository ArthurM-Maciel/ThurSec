"""Target validation — the defense against *argument injection* into argv.

ThurSec runs external tools (nmap, and more to come) with the operator's target
value placed directly on the command line, e.g. ``["nmap", "-sT", target]``.
Running without a shell already stops classic shell-injection (``; rm -rf``),
but it does **not** stop a target that *looks like a flag*: if ``target`` is
``"-sS"``, ``"--script=http-shellshock,exploit"`` or ``"-oN/tmp/pwned"``, the
tool parses it as one of its own options — bypassing any in-module allowlist and
potentially running arbitrary NSE scripts or writing files.

Appending ``--`` ("end of options") is **not** a reliable fix for nmap, so the
only safe stance is to *reject* a dangerous target rather than try to escape it.
That is what :func:`validate_target` does, and every module that forwards a
target into a subprocess argv should route it through here first.

A valid target is normalized and returned; anything implausible or dangerous
raises :class:`TargetError`. This module is pure stdlib and imports nothing from
the rest of ThurSec, so it is safe to use anywhere (no circular imports).
"""

from __future__ import annotations

from pathlib import Path

import ipaddress
import re
from urllib.parse import urlparse

__all__ = [
    "TargetError",
    "coerce_port",
    "is_network_target",
    "split_authority",
    "looks_like_cidr",
    "looks_like_local_path",
    "parse_endpoint",
    "validate_target",
]


class TargetError(Exception):
    """Raised when a target is empty, malformed, or unsafe to pass to a tool."""


# A single DNS label: 1-63 chars of letters/digits/hyphen, not starting or
# ending with a hyphen. The negative look-arounds reject the ``-sS`` shape.
_LABEL = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def looks_like_local_path(raw: str) -> bool:
    """True when *raw* is plainly a filesystem path, not a host or product.

    A single ``thursec run <alvo>`` fans out to every passive module, and the
    passive set mixes two kinds of subject: modules that read local files
    (secret_scan, server_configs) and modules that ask about a domain or a
    product (dns, whois, ct_subdomains, cve_lookup). Pointed at a repository,
    the second kind used to run anyway — ``vuln.cve_lookup`` keyword-searched
    the NVD for ``"."`` and returned CRITICAL findings reading "CVE-1999-0233
    affects .". Noise at that severity buries the real findings.

    The rule is deliberately biased toward *network*: skipping a module in
    silence is a false negative, and in a security tool that is worse than the
    noise this exists to remove. So a slash is not enough to call something a
    path — ``10.0.0.0/24``, ``example.com/admin`` and ``host:8443/`` are all
    legitimate network targets that contain one. Anything
    :func:`validate_target` accepts is treated as a target, never a path.

    What remains a path: the shapes that cannot be a host (``.``, ``..``,
    ``./``, ``../``, ``~``, an absolute or Windows/UNC path), and a bare name
    that `validate_target` rejects but that exists on disk.
    """
    text = (raw or "").strip()
    if not text:
        return False
    if "://" in text:  # a URL is a network target, not a path
        return False

    # Shapes that cannot be a hostname, whatever else they look like.
    if text in {".", ".."} or text.startswith(("./", "../", "~", "/", "\\")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", text):  # C:\... or C:/...
        return True

    # A relative path with a separator (``a/b``) has the same shape as
    # ``host/path``. Existence on disk decides: ``10.0.0.0/24`` and
    # ``example.com/admin`` are not files, a relative path usually is.
    if ("/" in text or "\\" in text):
        try:
            if Path(text).exists():
                return True
        except (OSError, ValueError):
            pass

    # A valid network target is a target, even with a slash in it (CIDR, path).
    try:
        validate_target(text)
        return False
    except TargetError:
        pass

    try:
        return Path(text).exists()
    except (OSError, ValueError):
        return False


def validate_target(raw: str) -> str:
    """Validate and normalize ``raw`` into a safe target string for a tool argv.

    Accepts a bare hostname, IPv4/IPv6 address, CIDR network, ``host:port``,
    a bracketed IPv6 literal (``[::1]`` / ``[::1]:80``), or a full URL (whose
    host is extracted). Returns the normalized host / IP / network.

    Raises :class:`TargetError` when the target is empty, begins with ``-``
    (would be read as a command-line flag — the core argument-injection guard),
    contains whitespace or control characters, or does not resemble a plausible
    host / IP / CIDR. Callers MUST NOT invoke the external tool when this raises.
    """
    if raw is None:
        raise TargetError("target is empty")
    s = raw.strip()

    if not s:
        raise TargetError("target is empty")
    if s.startswith("-"):
        raise TargetError(
            f"target {s!r} starts with '-' and would be interpreted as a "
            f"command-line flag (argument injection); refusing."
        )
    for ch in s:
        if ch.isspace():
            raise TargetError(f"target {s!r} contains whitespace")
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise TargetError(f"target {s!r} contains a control character")

    host = _extract_host(s)
    if not host:
        raise TargetError(f"could not extract a host from target {s!r}")

    # Uma porta impossível escrita no alvo é alvo malformado, não um detalhe a
    # descartar: deixar ``parse_endpoint`` cair no padrão faria o operador pedir
    # a 99999 e receber um relatório completo — cookies, cabeçalhos, métodos —
    # sobre o serviço da 443, sem uma linha dizendo que a porta foi ignorada.
    _reject_impossible_port(s)
    if host.startswith("-"):
        # e.g. a URL/authority whose host itself looks like a flag.
        raise TargetError(
            f"host {host!r} from target {s!r} starts with '-'; refusing."
        )

    # IP address or CIDR network (also covers full IPv6 literals).
    try:
        net = ipaddress.ip_network(host, strict=False)
    except ValueError:
        net = None
    if net is not None:
        if net.prefixlen == net.max_prefixlen and "/" not in host:
            return str(net.network_address)  # bare single address
        return str(net)

    if _is_hostname(host):
        return host.lower().rstrip(".")

    raise TargetError(
        f"target {s!r} is not a plausible host, IP address, CIDR or URL host"
    )


def _reject_impossible_port(target: str) -> None:
    """Levantar ``TargetError`` quando o alvo nomeia uma porta inviável."""
    t = target.strip()
    authority = urlparse(t).netloc if "://" in t else t.split("/", 1)[0]
    authority = authority.rpartition("@")[2]

    if authority.startswith("["):
        _, sep, rest = authority.partition("]")
        text = rest[1:] if sep and rest.startswith(":") else ""
    elif authority.count(":") == 1:
        _, _, text = authority.partition(":")
    else:
        text = ""

    if text and coerce_port(text) is None:
        raise TargetError(
            f"target {t!r} names port {text!r}, which is not a port number "
            f"between 1 and 65535"
        )


# --- host extraction -------------------------------------------------------
def _extract_host(s: str) -> str:
    """Pull the bare host out of a URL / host:port / bracketed IPv6 / CIDR.

    Mirrors the host parsing in ``core.scope`` but also understands bracketed
    IPv6 literals and CIDR, which matter when the result is handed to a tool.
    """
    # Full URL — let urllib pull out the (already unbracketed) host.
    if "://" in s:
        from urllib.parse import urlparse

        return (urlparse(s).hostname or "").strip()

    # Bracketed IPv6 literal, optionally with a :port — "[::1]" / "[::1]:80".
    if s.startswith("["):
        end = s.find("]")
        if end > 1:
            return s[1:end]
        return ""

    # Whole string is an IP or CIDR (covers IPv6 with its many colons).
    try:
        ipaddress.ip_network(s, strict=False)
        return s
    except ValueError:
        pass

    # host:port, com caminho e/ou userinfo possivelmente colados. A mesma
    # extração que o ``parse_endpoint`` usa, para que validar e interpretar o
    # alvo não possam discordar: ``user:senha@alvo`` virava o host "user" aqui
    # e "alvo" lá, ou seja, a varredura era autorizada contra um host e
    # executada contra outro.
    host, _ = split_authority(s)
    return host


def _is_hostname(host: str) -> bool:
    """True if ``host`` is a plausible DNS hostname (one or more valid labels)."""
    if not host or len(host) > 253:
        return False
    labels = host.rstrip(".").split(".")
    return all(_LABEL.match(label) for label in labels)

def coerce_port(value: object) -> int | None:
    """Uma porta vinda de opção de operador, ou ``None`` se não for uma.

    ``bool`` é recusado explicitamente, como em ``coerce_timeout``: a CLI
    converte o literal ``true`` em ``True`` e ``int(True)`` é ``1``, então
    ``--opt port=true`` varreria silenciosamente a porta 1 em vez de cair no
    padrão — um erro de digitação virando um alvo errado sem aviso.
    """
    if isinstance(value, bool):
        return None
    try:
        port = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def looks_like_cidr(raw: str) -> bool:
    """O alvo foi escrito em notação CIDR (``10.0.0.0/24``, ``10.0.0.1/32``)?

    Pergunta diferente de :func:`is_network_target`, que quer saber se a faixa
    tem mais de um endereço. Aqui o que importa é só que a barra pertence ao
    prefixo e não é começo de caminho — ``10.0.0.1/32`` é um host, mas ``/32``
    não é um endpoint.
    """
    text = (raw or "").strip()
    if "/" not in text:
        return False
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return True


def is_network_target(raw: str) -> bool:
    """O alvo é uma rede (CIDR com mais de um endereço), e não um host?

    Faz sentido para o ``recon.nmap``, que varre faixas. Não faz para quem
    abre uma conexão HTTP: ``parse_endpoint`` devolveria o endereço de rede,
    e o módulo auditaria *um* endereço enquanto rotula o achado com a faixa
    inteira — um relatório sobre 254 hosts tirado de um.
    """
    try:
        net = ipaddress.ip_network((raw or "").strip(), strict=False)
    except ValueError:
        return False
    return net.num_addresses > 1


def split_authority(target: str) -> tuple[str, int | None]:
    """``(host, port)`` a partir da autoridade, sem esquema, userinfo nem caminho.

    Uma função só para os três jeitos de escrever isso evita o que já aconteceu
    duas vezes aqui: consertar um ramo e esquecer o outro.
    """
    t = target.strip()
    authority = urlparse(t).netloc if "://" in t else t.split("/", 1)[0]
    # ``user:senha@host`` — o ':' do userinfo não é o da porta. Sem tirá-lo,
    # ``user:pass@alvo`` virava host "user", e o guarda de porta lia
    # "pass@alvo" como número de porta e recusava um alvo que era válido.
    authority = authority.rpartition("@")[2]

    if authority.startswith("["):
        # IPv6 literal: o endereço tem vários ':' por natureza, então só os
        # colchetes dizem onde ele termina.
        host, sep, rest = authority.partition("]")
        host = host[1:]
        port = coerce_port(rest[1:]) if sep and rest.startswith(":") else None
    elif authority.count(":") == 1:
        host, _, text = authority.partition(":")
        port = coerce_port(text)
    else:
        host, port = authority, None

    # Minúsculo, como ``validate_target`` já devolvia: sem isto,
    # ``https://ALVO.com`` era normalizado para os módulos que recebem argv
    # (nmap, nuclei) e chegava em caixa alta ao SNI, ao cabeçalho Host e ao
    # rótulo do achado dos módulos HTTP — a mesma divergência entre validar e
    # interpretar, estreitada para a caixa.
    return host.lower(), port


def parse_endpoint(target: str, options: dict) -> tuple[str, str, int]:
    """Derive ``(scheme, host, port)`` from the target and options.

    Estava duplicada, idêntica, em ``cookies``, ``http_methods`` e (com o
    caminho a mais) ``load_test``, e o ``tls_headers`` tinha uma quarta leitura
    própria que só olhava o host e assumia 443. Resultado: ``thursec run
    https://alvo:8443`` fazia uns falarem com 8443 e o outro com 443 — serviço
    diferente, ou nenhum — e os achados de um alvo saíam de lugares distintos.

    Understands a full URL (scheme/host/port honored), a bare ``host``, a
    ``host:port``, a forma IPv6 entre colchetes (``[::1]`` e ``[::1]:8443``) e
    userinfo (``user:senha@host``). Defaults to https/443; ``http`` with no
    port uses 80. ``options['port']`` overrides a port that is otherwise
    unspecified.
    """
    t = target.strip()
    scheme = (urlparse(t).scheme or "https").lower() if "://" in t else "https"
    host, port = split_authority(t)

    if port is None:
        port = coerce_port(options.get("port"))
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host, port
