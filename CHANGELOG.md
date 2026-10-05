# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/ArthurM-Maciel/ThurSec/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ArthurM-Maciel/ThurSec/releases/tag/v0.1.0
