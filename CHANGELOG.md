# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-05

Second release: adds the first **legitimate counterparts** to the vetoed
categories — controlled resilience testing (the lawful "DoS") and authorized
security-awareness training (the lawful "phishing") — on top of a new
double-barrier safety primitive for intrusive modules.

### Added

#### Core platform
- **Intrusive-confirmation primitive** (`V2.1`) — `INTRUSIVE` modules now run
  only behind a **double barrier**: the scope gate *and* an explicit operator
  confirmation (`--confirm-intrusive`, or an interactive prompt on a TTY).
  Without confirmation the module is skipped with a `skip_reason` and performs
  no action.
- New **`resilience` category** (`Category.RESILIENCE`) for the lawful "DoS"
  counterpart, always `INTRUSIVE`.

#### Modules
- **Resilience**
  - `resilience.load_test` — `INTRUSIVE`, scope-gated + confirmed controlled
    HTTP **GET**-only load/stress test of your *own* authorized infrastructure.
    Hard safety caps that cannot be removed: a **mandatory RPS ceiling** (no
    traffic without `max_rps`) under a **non-removable hard cap of 200 req/s**, a
    hard duration ceiling, and an **automatic error-rate kill-switch** that
    aborts the test on degradation. Targets pass the shared target validator.
- **Vulnerability**
  - `vuln.cve_lookup` — passive CVE lookup by product/version via the public NVD
    API (`PASSIVE`; queries an external base, never the target).
- **Configuration audit**
  - `config_audit.cookies` — active, read-only cookie security-flag audit
    (`Secure`/`HttpOnly`/`SameSite`).
  - `config_audit.server_configs` — passive nginx/sshd server-config linter.

#### Awareness subsystem
- **`thursec/awareness/`** + the **`awareness` CLI subcommand**
  (`awareness generate` / `awareness tally`) — the lawful counterpart to
  "phishing": renders purely educational landing pages and click tokens for an
  organization's *own* staff. **No credential capture** (no login form, no
  password field, no POST of secrets) and **no sending** (no SMTP, no transport).
  Requires a recorded **authorization** (`authorized_by` + `authorized_on`) and a
  recipient **allowlist** — any recipient outside it aborts generation. Metrics
  are aggregate and non-punitive (click tokens only, never a per-person score).

## [0.1.0] - 2026-10-05

First foundational release: a plugin-based security assessment toolkit for
**authorized** engagements, with a scope gate, structured findings, historical
tracking, and reporting.

### Added

#### Core platform
- Plugin engine with self-describing `Module` classes and automatic discovery
  (drop a file in a category package to add a module).
- **Scope gate** — `active`/`intrusive` modules refuse any target not listed in
  an authorized scope file (glob hosts, IPs, and CIDR ranges); passive modules
  run without a scope.
- Target validator and normalizer (host / IP / URL).
- Async, no-shell subprocess runner with hard per-module timeouts.
- Deduplicated, severity-ranked findings model.
- Reporting to JSON, Markdown, and HTML.
- Historical **findings store** (opt-in SQLite) with run-to-run **diff**
  (new / resolved / unchanged findings).
- HTML **posture dashboard** rendered over the findings store.
- Command-line interface (`thursec`): `list`, `run`, `diff`, `dashboard`.
- Textual **TUI** (`thursec-tui`) over the same engine primitives.

#### Modules (10 across 4 fronts)
- **Recon**
  - `recon.whois` — passive domain registration recon via RDAP/WHOIS.
  - `recon.dns` — passive DNS enumeration over DNS-over-HTTPS.
  - `recon.ct_subdomains` — passive subdomain discovery via Certificate
    Transparency logs.
  - `recon.nmap` — active port & service scan (wraps the external `nmap`
    binary).
- **Vulnerability**
  - `vuln.http_methods` — active HTTP methods & information-exposure audit
    (read-only).
  - `vuln.nuclei` — active template-based vulnerability scan (wraps the external
    `nuclei` binary).
- **Dependencies & secrets**
  - `deps_secrets.dep_audit` — passive dependency audit against the OSV
    database.
  - `deps_secrets.secret_scan` — local secret scan.
- **Configuration audit**
  - `config_audit.tls_headers` — TLS & HTTP security-headers audit (cert expiry,
    TLS version, security headers).
  - `config_audit.supabase` — Supabase posture audit.

#### Packaging & tooling
- Installable package (`hatchling` build) with `thursec` and `thursec-tui`
  entry points and `tui` / `dev` extras.
- Offline test suite (network mocked) covering core logic and modules.

[Unreleased]: https://github.com/ArthurM-Maciel/ThurSec/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ArthurM-Maciel/ThurSec/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ArthurM-Maciel/ThurSec/releases/tag/v0.1.0
