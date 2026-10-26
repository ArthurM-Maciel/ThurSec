# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **A bad TLS certificate was reported as if the host were unreachable.** Every
  failure in the TLS handshake collapsed into one MEDIUM "could not establish
  TLS connection" — the same sentence used when a port simply does not speak
  TLS. So the single most visible defect a site can have, a certificate that
  does not cover the domain, was filed under "could not connect", and the
  operator read it as an infrastructure hiccup instead of as "every visitor to
  this site hits a browser warning". Verification failures are now classified by
  the OpenSSL verify code into their own findings: hostname mismatch, expired,
  revoked, self-signed, incomplete chain, bad signature — HIGH or CRITICAL, with
  the fix that applies to each. An unrecognised verify code still reports HIGH,
  never MEDIUM: it is still a certificate the client refuses. Genuine connection
  failures keep the MEDIUM. Found against a real deployed site, which was
  serving its host's default wildcard certificate.

- **A rejected certificate blinded the whole module.** With the handshake
  aborted, the header audit never ran, so a site with a broken certificate also
  reported nothing about HSTS, CSP or any other header — the two defects that
  most often travel together. `--opt insecure_tls=true` now continues the audit
  over the unverified channel; it is opt-in, the certificate finding says the
  audit went on without verification, and each header finding carries
  `tls_verified: false` — the header findings, the disclosed `Server` banner,
  the negotiated protocol and the certificate validity alike, because none of it
  is known to come from the legitimate server. The banner is the one that
  matters most: it is what feeds `vuln.cve_lookup` by product and version.

- **The same target got three different stories in one run.** Each module built
  its own `HTTPSConnection` and swallowed any TLS error in the same blanket
  `except`, so against one host `tls_headers` reported HIGH "certificate does
  not cover this domain" while `cookies` and `http_methods` reported LOW "could
  not complete GET request — check whether the host serves HTTP(S) on this
  port", sending the operator to look at the port when the defect was the
  certificate. Both the TLS context and the reading of a refused certificate now
  live in `core/tls.py`, and all three modules use them.

- **The expiry check vanished exactly where it was most needed.** On the
  `insecure_tls` path the retry used `CERT_NONE`, and the stdlib then returns an
  empty `getpeercert()` — so a host with a self-signed certificate that was also
  two years expired reported the self-signed finding and nothing at all about
  expiry, which reads identically to "the dates are fine". The retry now first
  drops only the hostname check, keeping chain and dates validated, so the
  common case (a certificate that simply does not name this domain) still gets a
  full certificate read. When even that fails, the module says the validity was
  not checked instead of saying nothing.

- **`cookies` and `http_methods` crashed on a mistyped timeout.** Both called
  `float(ctx.options.get("timeout"))` unguarded, so `--opt timeout=rapido`
  raised inside the request and was reported as a connection failure — pointing
  the operator at the target instead of at their own command line. They now use
  the same `coerce_timeout` as the rest of the tool.

- **One defect counted three times.** With all three network modules now reading
  a refused certificate correctly, a single bad certificate produced three HIGH
  findings — one per module — and the summary said `HIGH 3` for one problem.
  `Finding.fingerprint` has to include the module (the SQLite history is indexed
  by it), so a finding may now declare `metadata["dedup_key"]` instead, and
  `Report.collapsed()` folds those together for reading, listing the other
  modules under `also_seen_by`. The collapse is strictly a *view*: `add()` still
  keeps every finding and the store still receives all of them, because
  collapsing before saving would make `thursec diff` announce the absorbed
  modules' findings as "disappeared" — and since which one survives depends on
  execution order, a run by category and a full run would store different
  fingerprints for the same defect and produce a spurious appeared/disappeared
  pair on every diff.

- **`tls_headers` ignored a port given in the target.** It read only the host and
  assumed 443, while `cookies` and `http_methods` honoured `https://host:8443` —
  so one target produced findings from two different ports, one of them possibly
  a different service or nothing at all. The target parsing was also duplicated
  verbatim in those two modules; all three now share `core.target.parse_endpoint`.

- **The header audit was weakened further than the handshake that preceded it.**
  One flag was doing two jobs — what to tell the reader, and how much to demand
  of the server. When only the hostname check had been dropped (chain and dates
  still validated), the header request fell all the way to `CERT_NONE` anyway.
  The two are now separate, and the request keeps exactly the validation the
  probe kept.

- **A finding said the audit continued when it had not.** The certificate
  finding was built before the unverified retry was attempted, so when that
  retry also failed, the report carried "the audit continued over unverified
  TLS" next to "could not establish TLS connection". It is now built after the
  outcome is known in all three modules, and on that path it does not suggest
  `insecure_tls` either — the operator had already passed it. Because the three
  share a `dedup_key`, the collapsed view keeps whichever module ran first, so a
  wrong description in any one of them could be the only one the reader sees.

- **The TLS audit kept inventing special rules for the port, and each one made
  it scan a different port from the other modules on the same host.** Across
  several attempts it ignored `--opt port=`, then accepted only the
  module-scoped spelling, then fell back to 443 for an `http` target — and each
  rule reintroduced the cross-module divergence that sharing one parser existed
  to remove, because for a bare or `https` target the other modules read that
  same port as the TLS port too. It now reads the target exactly as they do,
  options included. When the target names a cleartext service (`http://alvo`,
  with or without a port), the module says so and audits nothing, instead of
  silently swapping the port the operator wrote for 443 and reporting on a
  service nobody asked about.

- **Only `http://` was treated as cleartext.** The TLS audit tested the scheme
  for equality with `http`, but `parse_endpoint` gives every non-`https` scheme
  port 80, so `ws://alvo` (or `ftp://`, or anything else the operator writes)
  fell through to the handshake and produced a false "could not establish TLS
  connection". Anything that is not `https` is now reported as having no TLS to
  audit.

- **Host case diverged between validating a target and acting on it.**
  `validate_target` lowercases, the shared authority split did not, so
  `https://ALVO.com` was normalised for the argv-based modules (nmap, nuclei)
  and handed to the HTTP modules in upper case as SNI, as the `Host` header and
  as the finding label. The same narrowing applies to the scope gate, which also
  now normalises an IP target.

- **A scope file authorising a range refused that very range.** `_match`
  compared the target as a single address, which raises for a network string
  and fell through to "no match", so `--scope` listing `10.0.0.0/24` rejected
  `thursec run 10.0.0.0/24` — the target the file authorises literally, in the
  module (`recon.nmap`) ranges exist for. A range target is now authorised when
  it sits entirely inside an authorised range; a *wider* range still is not, so
  the boundary does not loosen.

- **A module-scoped `insecure_tls` made the collapsed finding deny what
  happened.** The flag is read per module, so `--opt
  config_audit.cookies.insecure_tls=true` leaves one module continuing and
  another stopping; both emitted a certificate finding under the same key, and
  the collapse kept the one that stopped — denying a continuation that did
  happen and dropping the unverified marker with it. The flag is part of the
  key now; with one flag for the whole run, which is the normal case, nothing
  changes.

- **Collapsing the dashboard diff made severity changes disappear.** The
  `changed_severity` entries are assembled by hand in the store and carry no
  fingerprint and no metadata, so every one of them keyed to the empty string
  and the whole bucket folded into a single row: three findings whose severity
  changed were shown as one, and the other two — possibly the CRITICAL one —
  vanished from the page. The grouping now refuses to fold rows it cannot
  identify, and those rows are grouped on the identity they do have: target,
  title and the two severities.

- **The three reading surfaces still disagreed with each other.** `thursec run`
  collapsed, the dashboard collapsed, and `thursec diff` printed the store rows
  raw — so one certificate was `HIGH 1` in the summary, one row on the
  dashboard and "New (3)" in the diff. All three group the same way now, and
  the grouping helpers live next to the key they use rather than being reached
  into from another module.

- **The dashboard computed "also seen by" and never showed it**, under a
  top-level key instead of the `metadata` one the report uses, so a consumer
  reading the documented shape would never find it and the page presented as
  one module's observation what three modules had found. It is written where
  the report writes it, merged symmetrically, and rendered next to the module.

- **The scope gate and the modules read different hosts.** Aligning target
  validation with endpoint parsing left `core.scope` on its own third copy, so
  `admin:senha@alvo` had the scope authorising the host `admin` while every
  network module connected to `alvo` — authorised against one host, run against
  another, which is the one thing a scope file exists to prevent. The scope now
  uses the same extraction, keeping a CIDR as a network so the authorisation
  boundary does not widen.

- **A network range was audited as if it were a host.** `parse_endpoint` returns
  the network address for `10.0.0.0/24`, so the HTTP modules audited
  `10.0.0.0` and labelled every finding with the whole range — a report about
  254 hosts drawn from one. They now say a range is not a host and point at
  `recon.nmap` — `resilience.load_test` included, where it matters most, since
  that is the INTRUSIVE one and the load would all have gone to the network
  address under a finding labelled with the whole range. There the same slash
  also became the request path, so a load test against `10.0.0.0/24` hammered
  `/24` and reported latency for an endpoint that does not exist.

- **A URL with credentials was refused, and parsed as a different host.** The
  new port guard counted colons in the netloc, so `https://user:pass@alvo` read
  `pass@alvo` as the port and rejected a target that had worked before. Without
  a scheme it was worse and older: `user:pass@alvo` validated as the host `user`
  while the modules connected to `alvo` — authorised against one host, run
  against another. Host extraction and endpoint parsing now go through one
  function that strips scheme, userinfo and path, so validating a target and
  acting on it can no longer disagree.

- **The dashboard and the run summary disagreed.** The store keeps every
  finding on purpose, which is what makes `thursec diff` stable, but the
  dashboard read those rows straight — so a run printed `HIGH 1` and
  `thursec dashboard` showed `HIGH 3` for that same run. Both now group through
  the same `collapse_key`, the diff section included: otherwise one page showed
  `HIGH 1` in the tiles and listed the same certificate three times right below
  them.

- **An impossible port was silently replaced by the default.** Centralising the
  parsing introduced this: `alvo:99999` used to fail loudly on connect, and
  afterwards all four network modules quietly audited 443 and handed back a full
  report — cookies, headers, methods, server banner — about a different service,
  with nothing saying the requested port had been dropped. A port written into
  the target is now rejected by `validate_target`, and `--opt port=` by the CLI,
  so both say so instead of auditing something else.

- **The path-stripping fix was applied to one branch and not the other.**
  `alvo:8443/admin` kept its port but `[::1]:8443/admin` lost it, because the
  bracketed-IPv6 branch never got the same treatment. The authority is now
  separated once, before the branches.

- **`resilience.load_test` silently measured a different endpoint.** It
  recovered the request path only from a target carrying a scheme, so
  `alvo/admin` hammered `/` while the report named `/admin`. In a module that
  generates real load, measuring the wrong endpoint without saying so is the
  worst possible outcome.

- **The TUI's table rebuild threw away the reader's place.** Collapsing requires
  redrawing rather than appending, but each module that finished during a run
  sent the row cursor back to the top. The cursor is restored after the refill.

- **A mistyped port killed every network module at once.** `urlparse(...).port`
  *raises* `ValueError` outside 0–65535, and the shared parser read it directly,
  so `https://alvo:99999` turned `cookies`, `http_methods`, `tls_headers` and
  `load_test` into module ERRORs with zero findings in the same run — the
  opposite of what centralising the parsing was for. The coercion decides now,
  not the exception.

- **A path glued to the target ate the port.** `alvo:8443/` left the port text
  as `"8443/"`, which coerced to nothing and fell back to 443 — the operator
  asked for 8443 and got a report about whatever runs on 443. And `alvo/admin`
  became the literal hostname `alvo/admin`, which every module then reported as
  a connection failure against a host that does not exist. Both were present in
  all four copies; centralising the parser is what made them fixable once.

- **The collapsed finding could carry the wrong narrative — and fixing that the
  obvious way brought the double count back.** With `insecure_tls=true` one
  module's retry can succeed while another's fails, so two certificate findings
  described opposite outcomes; collapsing kept whichever module sorted first and
  the report asserted a continuation that had not happened for it. Putting the
  outcome in the `dedup_key` fixed the sentence and split one certificate into
  two HIGH findings again. The way out was to stop describing the per-module
  outcome there at all: the sentence now states the *run configuration*, which
  is identical for every module, and what each one managed to do is already said
  by its own adjacent finding. One defect, one count, no false claim.

- **The TUI counted what the CLI collapsed.** `thursec tui` never built a
  `Report`, so on the same target with the same modules it showed HIGH 3 for a
  certificate the CLI reports as HIGH 1 — the exact triple-count the dedup was
  added to remove. It routes through `Report` now, so both agree and the store
  still receives every finding.

- **One flag meant two different trust levels in the same run.** `tls_headers`
  retried a refused certificate by dropping only the hostname check, keeping the
  chain and dates validated, while `cookies` and `http_methods` dropped straight
  to `CERT_NONE` — accepting any certificate at all, including an attacker's —
  for the same `insecure_tls=true` on the same target, with nothing in the
  output to tell the operator which one they got. All three now take the same
  two steps, reaching `CERT_NONE` only when the chain itself does not hold.

- **`--opt port=true` scanned port 1.** `int(True)` is `1`, the same trap
  `coerce_timeout` already guards against. Port coercion is now centralised and
  rejects booleans, non-numbers and anything outside 1–65535, falling back to
  the scheme default.

- **`config_audit.tls_headers` never validated its target.** The other two
  network modules refuse an implausible or flag-shaped target before opening a
  socket; this one handed the literal string to `socket.create_connection` and
  reported "could not establish TLS connection" — blaming the target for what
  was a malformed command line.

- **A bracketed IPv6 target with a port was parsed as a hostname.** `[::1]:8443`
  has more than one colon, so it fell into the bare-host branch and became the
  literal host `[::1]:8443` on port 443, which every network module then
  reported as a connection failure. Fixed once, in the now-shared parser.

- **The collapse could drop a finding of a different severity.** Two findings
  sharing a `dedup_key` but differing in severity were folded together with the
  survivor chosen by module name rather than by worst case, so the graver one
  vanished from the report and the counts while remaining in the store — the
  very appeared/disappeared noise the dedup exists to prevent. Severity is now
  part of the collapse key.

- **The certificate finding from `tls_headers` was missing the
  `tls_verified` mark** that the other two modules stamped on theirs. Since the
  three share a `dedup_key` and the collapsed view keeps one of them, a consumer
  filtering on that key saw the finding marked or not depending on which modules
  the run happened to select.

- **The collapsed view picked its survivor by arrival order.** The surviving
  finding's `module` and `fingerprint` go into the JSON report, so
  `-c config_audit` and a full run could export different ones for the same
  defect — the same instability that `add()` already avoids for the SQLite
  store. The survivor is now the lowest module id.

- **The target parsing existed in four near-identical copies.** The fourth, in
  `resilience.load_test`, now builds on `parse_endpoint` too; only the request
  path remains specific to it.

- **An empty `also_seen_by` shipped on ordinary duplicates.** The key was
  inserted before the check for a differing module, so any plain duplicate left
  `"also_seen_by": []` in the metadata of the surviving finding — and that key
  reaches the JSON report and the store, misleading any consumer that tests for
  its presence.

- **`config_audit.supabase_audit` had the same `bool()` defect as `nuclei`, with
  worse consequences.** `service_key_in_client` *creates* a finding rather than
  disarming a check, so called from Python or the Claude Code skill with the
  string `"false"`, it fabricated a CRITICAL "service_role key is used in
  client-side code" about a key that was never in client code.

- **`bool("false")` is `True`.** `vuln.nuclei` read `allow_intrusive` — the flag
  that drops the exclusion of destructive templates — with a bare `bool()`. The
  CLI coerces `false` before the module sees it, so this was unreachable from
  the command line, but a module is also called from Python (tests, the Claude
  Code skill), and there the string survives intact and inverts the intent of
  whoever wrote it. A shared `coerce_bool` now reads these flags, and — like
  `coerce_timeout` — an unrecognised value falls back to the default rather than
  counting as true: otherwise a transposed `flase` would *enable* precisely the
  flags that disarm a protection.

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

- **`--opt insecure_tls=true`** for `config_audit.tls_headers`,
  `config_audit.cookies` and `vuln.http_methods`: continue the audit against a
  host whose certificate is itself the defect. Off by default, and every finding
  obtained that way is marked `tls_verified: false`.
- **Tests for `config_audit.tls_headers`**, which had none.
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
