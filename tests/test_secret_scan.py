import pytest

from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.modules.deps_secrets.secret_scan import SecretScan

FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


async def _run(target: str):
    return await SecretScan().run(RunContext(target=target))


@pytest.mark.asyncio
async def test_detects_aws_key_and_redacts(tmp_path):
    leaky = tmp_path / "config.py"
    leaky.write_text(f'AWS_ACCESS_KEY_ID = "{FAKE_AWS_KEY}"\n')
    (tmp_path / "clean.py").write_text("x = 1\nprint('hello world')\n")

    findings = await _run(str(tmp_path))

    aws = [f for f in findings if "AWS Access Key" in f.title]
    assert len(aws) == 1
    f = aws[0]

    # High-severity detection.
    assert f.severity >= Severity.HIGH
    # Evidence is redacted: the full secret must NOT appear anywhere.
    assert FAKE_AWS_KEY not in f.evidence
    assert "AKIA" in f.evidence and "*" in f.evidence
    # Location metadata is populated.
    assert f.metadata["file"] == "config.py"
    assert f.metadata["line"] == 1


@pytest.mark.asyncio
async def test_clean_file_produces_no_finding(tmp_path):
    (tmp_path / "clean.py").write_text("greeting = 'hello world'\ntotal = 2 + 2\n")
    findings = await _run(str(tmp_path))
    assert findings == []


@pytest.mark.asyncio
async def test_git_dir_is_skipped(tmp_path):
    gitdir = tmp_path / ".git"
    gitdir.mkdir()
    (gitdir / "leaked.txt").write_text(f'key = "{FAKE_AWS_KEY}"\n')

    findings = await _run(str(tmp_path))
    assert findings == []


@pytest.mark.asyncio
async def test_private_key_is_critical(tmp_path):
    (tmp_path / "id_rsa").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"
    )
    findings = await _run(str(tmp_path))
    pk = [f for f in findings if "Private Key" in f.title]
    assert len(pk) == 1
    assert pk[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_binary_file_is_skipped(tmp_path):
    blob = tmp_path / "data.bin"
    blob.write_bytes(b"\x00\x01\x02" + FAKE_AWS_KEY.encode() + b"\x00")
    findings = await _run(str(tmp_path))
    assert findings == []


@pytest.mark.asyncio
async def test_low_entropy_assignment_is_ignored(tmp_path):
    # Looks like a secret assignment but the value is a plain word -> no finding.
    (tmp_path / "settings.py").write_text('password = "aaaaaaaaaaaaaaaaaa"\n')
    findings = await _run(str(tmp_path))
    assert findings == []


@pytest.mark.asyncio
async def test_missing_target_is_graceful(tmp_path):
    findings = await _run(str(tmp_path / "does_not_exist"))
    # No crash; an informational finding is fine.
    assert all(f.severity == Severity.INFO for f in findings)
