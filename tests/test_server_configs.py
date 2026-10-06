import pytest

from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.core.i18n import get_lang, set_lang
from thursec.modules.config_audit.server_configs import ServerConfigAudit


@pytest.fixture(autouse=True)
def _force_en():
    """These assertions check English text; pin the language and restore it."""
    previous = get_lang()
    set_lang("en")
    try:
        yield
    finally:
        set_lang(previous)

INSECURE_NGINX = """\
http {
    server_tokens on;
    server {
        listen 443 ssl;
        server_name example.com;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        location /files {
            autoindex on;
        }
    }
}
"""

SECURE_NGINX = """\
http {
    server_tokens off;
    server {
        listen 443 ssl;
        server_name example.com;
        ssl_protocols TLSv1.2 TLSv1.3;
        add_header Strict-Transport-Security "max-age=63072000" always;
        add_header X-Content-Type-Options nosniff;
        add_header X-Frame-Options DENY;
        add_header Content-Security-Policy "default-src 'self'";
        location /files {
            autoindex off;
        }
    }
}
"""

INSECURE_SSHD = """\
# sample sshd_config
Protocol 1
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
X11Forwarding yes
"""

SECURE_SSHD = """\
# hardened sshd_config
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
"""


async def _run(target):
    return await ServerConfigAudit().run(RunContext(target=str(target)))


def _by_rule(findings, fragment):
    return [f for f in findings if fragment in f.title]


@pytest.mark.asyncio
async def test_insecure_nginx_directives_detected_with_severity_and_line(tmp_path):
    cfg = tmp_path / "nginx.conf"
    cfg.write_text(INSECURE_NGINX)

    findings = await _run(cfg)

    tokens = _by_rule(findings, "server_tokens on")
    assert len(tokens) == 1
    assert tokens[0].severity == Severity.LOW
    assert tokens[0].metadata["line"] == 2
    assert tokens[0].metadata["config_type"] == "nginx"
    assert "nginx.conf:2:" in tokens[0].evidence

    tls = _by_rule(findings, "ssl_protocols allows obsolete TLS")
    assert len(tls) == 1
    assert tls[0].severity == Severity.MEDIUM
    assert tls[0].metadata["line"] == 6

    autoindex = _by_rule(findings, "autoindex on")
    assert len(autoindex) == 1
    assert autoindex[0].severity == Severity.MEDIUM
    assert autoindex[0].metadata["line"] == 8


@pytest.mark.asyncio
async def test_secure_nginx_has_no_insecure_findings(tmp_path):
    cfg = tmp_path / "nginx.conf"
    cfg.write_text(SECURE_NGINX)

    findings = await _run(cfg)

    # No LOW/MEDIUM/HIGH/CRITICAL issues — only (at most) INFO header notes,
    # and here every expected header is present, so nothing at all.
    serious = [f for f in findings if f.severity > Severity.INFO]
    assert serious == []
    assert findings == []


@pytest.mark.asyncio
async def test_insecure_sshd_directives_detected_with_severity_and_line(tmp_path):
    cfg = tmp_path / "sshd_config"
    cfg.write_text(INSECURE_SSHD)

    findings = await _run(cfg)

    proto = _by_rule(findings, "Protocol 1")
    assert len(proto) == 1
    assert proto[0].severity == Severity.HIGH
    assert proto[0].metadata["line"] == 2

    root = _by_rule(findings, "PermitRootLogin yes")
    assert len(root) == 1
    assert root[0].severity == Severity.HIGH
    assert root[0].metadata["line"] == 3
    assert "sshd_config:3:" in root[0].evidence

    passwd = _by_rule(findings, "PasswordAuthentication yes")
    assert len(passwd) == 1
    assert passwd[0].severity == Severity.MEDIUM
    assert passwd[0].metadata["line"] == 4

    empty = _by_rule(findings, "PermitEmptyPasswords yes")
    assert len(empty) == 1
    assert empty[0].severity == Severity.CRITICAL
    assert empty[0].metadata["line"] == 5

    x11 = _by_rule(findings, "X11Forwarding yes")
    assert len(x11) == 1
    assert x11[0].severity == Severity.LOW
    assert x11[0].metadata["line"] == 6


@pytest.mark.asyncio
async def test_secure_sshd_produces_no_findings(tmp_path):
    cfg = tmp_path / "sshd_config"
    cfg.write_text(SECURE_SSHD)

    findings = await _run(cfg)
    assert findings == []


@pytest.mark.asyncio
async def test_directory_target_scans_both_configs(tmp_path):
    (tmp_path / "nginx.conf").write_text(INSECURE_NGINX)
    (tmp_path / "sshd_config").write_text(INSECURE_SSHD)

    findings = await _run(tmp_path)

    assert _by_rule(findings, "PermitRootLogin yes")
    assert _by_rule(findings, "autoindex on")
    # Every directive finding carries file:line location metadata (the optional
    # INFO header notes have a file but no single offending line).
    located = [f for f in findings if "line" in f.metadata]
    assert located
    for f in located:
        assert "file" in f.metadata and f"{f.metadata['line']}" in f.evidence


@pytest.mark.asyncio
async def test_commented_directives_are_ignored(tmp_path):
    cfg = tmp_path / "sshd_config"
    cfg.write_text("# PermitRootLogin yes\n#PasswordAuthentication yes\n")

    findings = await _run(cfg)
    assert findings == []


@pytest.mark.asyncio
async def test_binary_file_is_skipped(tmp_path):
    blob = tmp_path / "nginx.conf"
    blob.write_bytes(b"\x00\x01server_tokens on;\x00")

    findings = await _run(blob)
    assert findings == []


@pytest.mark.asyncio
async def test_missing_target_returns_info(tmp_path):
    findings = await _run(tmp_path / "nope" / "nginx.conf")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO


@pytest.mark.asyncio
async def test_missing_security_headers_info_on_insecure_nginx(tmp_path):
    cfg = tmp_path / "nginx.conf"
    cfg.write_text(INSECURE_NGINX)

    findings = await _run(cfg)
    headers = [f for f in findings if "missing security header" in f.title]
    assert headers  # insecure sample declares no add_header directives
    assert all(h.severity == Severity.INFO for h in headers)
