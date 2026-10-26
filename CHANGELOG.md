# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **The dependency audit no longer takes minutes.** OSV was queried one package
  at a time, so a lock file of a few hundred packages serialised into 2+ minutes
  for a landing page. The queries are independent, so they now run with a
  concurrency cap of 8 — the same project went to 32 seconds for all 284
  packages. The cap keeps a free public API from being hammered.

- **A repository audit was mostly noise, at the top severity.** `thursec run .`
  fans out to every passive module, and the domain/product ones ran against the
  path anyway: `vuln.cve_lookup` keyword-searched the NVD for `"."` and returned
  **7 CRITICAL** findings reading "CVE-1999-0233 affects .", while `recon.dns`,
  `recon.whois` and `recon.ct_subdomains` added "could not look up" noise and
  `config_audit.electron_fuses` handed the repository directory to REA. A real
  audit of this repo reported CRITICAL 10 / HIGH 17 / MEDIUM 29, of which
  almost all was meaningless — which buries the real findings and teaches the
  operator to distrust the severity column. Those modules now stay silent when
  the target is plainly a local path (`core.target.looks_like_local_path`), and
  `electron_fuses` requires an `.app` bundle or a file rather than any existing
  directory. The same audit now reports CRITICAL 0 / HIGH 2 after excluding
  fixtures.

  The path test is biased toward *network* on purpose: a slash does not make a
  path, because `10.0.0.0/24`, `example.com/admin` and `host:8443/` are all
  legitimate targets that contain one. Anything `validate_target` accepts stays
  a target — skipping a real target in silence is a false negative, and in a
  security tool that is worse than the noise being removed. A relative `a/b`
  is settled by whether it exists on disk.

- **`deps_secrets.secret_scan` missed an AWS secret key in a `.env`.** The rule
  required the value to be quoted, so it matched `aws_secret_access_key = "..."`
  in source but not `AWS_SECRET_ACCESS_KEY=...` in a `.env` file or
  `aws_secret_access_key: ...` in YAML — the two most likely places a real key
  leaks. Quotes are now optional, with a quote *or* a `=`/`:` separator still
  required so prose mentioning "aws secret" cannot trigger it. Found by
  scanning a fixture with planted credentials and comparing against ground
  truth; no test covered the Secret Access Key rule before (only the Access Key
  ID), so the gap was invisible to the suite.

- **Version is now read from a single source.** `pyproject.toml` takes its
  version from `thursec/__init__.py` (hatch dynamic version), so `thursec
  --version` can no longer drift behind the changelog — it reported `0.1.0`
  while the project was already at `0.2.0`. The HTTP `User-Agent` of every
  module that calls out now derives from `__version__` too, instead of a
  hardcoded `ThurSec/0.1` — including the four that send it as a request header
  (`vuln.http_methods`, `config_audit.tls_headers`, `config_audit.cookies` and
  `resilience.load_test`), whose traffic is the most visible to a target's logs.
- **`DEMO.md`'s sample transcript no longer disagrees with `--version`.**
- **Network timeouts no longer expire on healthy lookups.** `recon.ct_subdomains`
  went from 15s to 45s (crt.sh aggregates every public CT log and routinely
  takes tens of seconds) and `vuln.cve_lookup` from 20s to 30s. Both were
  turning in a LOW "could not query" finding on perfectly good runs.
- **Transient crt.sh failures are retried.** crt.sh returns intermittent
  429/5xx even while healthy — measured at roughly 2 of 3 requests, with the
  502 coming back in under a second — so a single attempt turned in a false
  "could not query" finding on most runs. `recon.ct_subdomains` now makes up to
  3 attempts, covering dropped and timed-out connections as well as explicit
  HTTP error responses, including the ones `urllib` wraps in a `URLError`, and
  honours `Retry-After` on a 429 (clamped to 30s). Permanent failures are not
  retried: an NXDOMAIN or a TLS verification error does not improve on a second
  try, so retrying one would only delay the same finding.
- **A malformed `--opt timeout=` no longer masquerades as a network failure.**
  Both modules now coerce the option before the request, so a typo, zero or a
  negative value falls back to the default instead of being swallowed into a
  LOW "could not query" finding.
- **`--opt api_key=` can force an anonymous NVD query** even with `NVD_API_KEY`
  exported; previously an explicitly empty option fell through to the
  environment.

### Added

- **An unknown `--opt` module prefix is now a usage error.** A dotted key is
  addressed to a module id, so a typo in that prefix (`recon.dns_enum.timeout`
  — the module is `recon.dns`) would otherwise be dropped as silently as a key
  meant for a module that is not running, leaving the operator with default
  values and no sign their option was ignored. The CLI validates the prefix
  against the registry and fails like it does for a missing `=`.
- **Module-scoped `--opt` keys.** `--opt` was a single flat namespace handed to
  every module, so `-c vuln --opt timeout=60` cut `vuln.nuclei` from its 600s
  default down to 60 and made it report a bogus timeout. A key may now carry a
  module id — `--opt vuln.cve_lookup.timeout=60` — which wins over the bare key
  for that module and is invisible to the others. Bare keys still apply to the
  whole run, so nothing existing changes. Resolution lives in
  `core.context.scoped_options`; modules read `ctx.options` exactly as before.
- **Configurable per-run timeout** for `recon.ct_subdomains` and
  `vuln.cve_lookup` via `--opt timeout=<seconds>`. The option is a *total*
  budget, not per attempt: with retries, a per-attempt reading would multiply a
  45s timeout into ~195s of stalled run, and modules run sequentially.
- **`core.context.coerce_timeout`**, one shared timeout coercion replacing four
  near-identical copies (`recon.nmap`, `vuln.nuclei`, `resilience.load_test`
  and the two added here). It also rejects booleans, which the copies accepted:
  the CLI turns the literal `true` into `True` and `float(True)` is `1.0`, so
  `--opt timeout=true` used to impose a one-second timeout — the shortest
  possible, and exactly the false "could not query" finding the coercion exists
  to prevent.
- **Optional NVD API key** for `vuln.cve_lookup`, from `--opt api_key=...` or
  the `NVD_API_KEY` environment variable, sent as the `apiKey` request header.
  It raises NIST's rate limit from 5 to 50 requests per window. The key is
  never logged or written to a report.

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
