# ThurSec

[![CI](https://github.com/ArthurM-Maciel/ThurSec/actions/workflows/ci.yml/badge.svg)](https://github.com/ArthurM-Maciel/ThurSec/actions/workflows/ci.yml)

**Modular security assessment toolkit — for authorized engagements.**

ThurSec is a plugin-based orchestrator for security work: recon, vulnerability
scanning, dependency & secret analysis, and configuration auditing — organized
behind one consistent interface, with structured findings and shareable
reports. It is built for **authorized** work: your own infrastructure,
contracted penetration tests, CTFs, and labs.

> ThurSec deliberately does **not** include denial-of-service, phishing /
> credential-harvesting, or remote-access-trojan tooling. Those categories exist
> to cause harm without consent and are out of scope for this project.

## Why it exists

Menu-driven "all-in-one" toolkits are convenient but usually brittle: they shell
out with `os.system`, have no timeouts, no scope control, and no reporting.
ThurSec keeps the convenience and fixes the engineering:

| | ThurSec |
| --- | --- |
| Architecture | Self-describing plugin classes; drop in a file to add a module |
| Execution | Async, no-shell subprocess runner with hard timeouts |
| Authorization | **Scope gate** — active modules refuse out-of-scope targets |
| Output | Deduplicated, severity-ranked findings → JSON / Markdown / HTML |
| Tested | Core logic (scope, findings, engine) covered by `pytest` |

## The scope gate

Any module that touches a target (`active`/`intrusive`) will only run against a
host listed in an authorized scope file. This makes staying in-scope the default
and going out-of-scope an explicit act.

```yaml
# scope.yaml  (copy from scope.example.yaml; git-ignored)
engagement: "Raiô Benefícios — internal baseline"
authorized_by: "arthur.maciel@raiobeneficios.com"
expires: 2026-12-31
targets:
  - "*.lab.example"      # one label: a.lab.example ✓  deep.sub.lab.example ✗
  - "10.0.0.5"
  - "192.168.56.0/24"
```

Passive modules (no packets to the target) run without a scope.

## Install

### As a CLI tool (pipx)

The quickest way to get the `thursec` command on your PATH, isolated in its own
environment:

```bash
pipx install "thursec[tui]"            # from a local checkout, run inside the repo:
pipx install ".[tui]"
# …or straight from GitHub:
pipx install "git+https://github.com/ArthurM-Maciel/ThurSec.git"
```

Drop the `[tui]` extra if you only need the CLI.

### From source (development)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[tui,dev]"
```

### With Docker

The image ships the CLI with all passive modules ready to go:

```bash
docker build -t thursec .
docker run --rm thursec list
docker run --rm thursec run example.com -m config_audit.tls_headers
```

To assess a target from a scope file, mount it into the container:

```bash
docker run --rm -v "$PWD/scope.yaml:/app/scope.yaml:ro" \
  thursec run host.lab.example -c config_audit --scope /app/scope.yaml
```

> The active modules `recon.nmap` and `vuln.nuclei` shell out to the external
> `nmap` / `nuclei` binaries, which are **not** bundled in the slim base image.
> Install them in a derived image or run on a host that provides them.

## Usage

```bash
thursec list                                      # see available modules
thursec run example.com -m config_audit.tls_headers --scope scope.yaml
thursec run host.lab.example -c config_audit --scope scope.yaml -o report.html
```

A bare `thursec run <target>` (no `-m`/`-c`) runs **passive modules only**, so it
can never touch an out-of-scope host by accident.

For a guided, fully self-contained walkthrough (safe, localhost-only), see
[`DEMO.md`](DEMO.md).

## Writing a module

A module is one class. The engine discovers it, handles scope, timing and
errors; you just return findings.

```python
from thursec.core.context import RunContext
from thursec.core.finding import Severity
from thursec.core.module import Category, Intensity, Module

class MyCheck(Module):
    id = "config_audit.my_check"
    name = "My check"
    category = Category.CONFIG_AUDIT
    intensity = Intensity.ACTIVE          # => scope-gated
    requires_tools = ()                    # external binaries, if any

    async def run(self, ctx: RunContext):
        return [ctx.finding(self.id, "Something worth reporting", Severity.LOW,
                            recommendation="Do the thing.")]
```

## Project layout

```
thursec/
  core/        finding · scope · module · runner · engine · report · context
  modules/     config_audit/ · recon/ · …  (each category is a package)
  cli.py       command-line entry point
tests/         scope, findings, and engine coverage
```

## Status

Early foundation. Working today: plugin engine, scope gate, async runner,
reporting (JSON/MD/HTML), and the `config_audit.tls_headers` module
(pure-stdlib: cert expiry, TLS version, security headers).

## License

MIT © Arthur Maciel
