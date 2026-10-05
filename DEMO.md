# ThurSec — Demo Runbook

A **safe, fully self-contained** walkthrough of ThurSec. Nothing here touches the
public internet as a *target*, no external host, no AWS, no paid service. The
only "target" we attack is a throwaway `python3 -m http.server` bound to
`localhost`, and every scope file authorizes only `127.0.0.1` / `localhost`.

> Two modules (`vuln.cve_lookup`, `deps_secrets.dep_audit`) make an **outbound**
> call to a public *vulnerability database* (NVD / OSV) — never to your target.
> If you run fully offline, their network errors are handled gracefully and the
> demo still completes (see the notes on those steps).

Every command below was executed against this repository and the sample output
shown is **real** (lightly trimmed). Your CVE counts and timings will differ.

---

## 0. One-time setup (verified)

```bash
# From the repo root.
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[tui]"
```

```console
$ thursec --version
ThurSec 0.1.0
```

### Bring up the local lab target

```bash
mkdir -p /tmp/thursec-demo
python3 -m http.server 8000 --directory /tmp/thursec-demo &   # localhost:8000
```

```console
$ curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/
200
```

### Create the scope file (authorizes ONLY localhost)

```bash
cat > scope.yaml <<'YAML'
engagement: "ThurSec local demo"
authorized_by: "arthur.maciel@raiobeneficios.com"
expires: 2026-12-31
targets:
  - "127.0.0.1"
  - "localhost"
YAML
```

`scope.yaml` and `scope.*.yaml` are git-ignored on purpose — scope files carry
engagement/authorization data and must never be committed.

### Create a sample `sshd_config` to lint (step 3)

```bash
cat > /tmp/thursec-demo/sshd_config <<'EOF'
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding yes
PermitEmptyPasswords yes
EOF
```

---

## 1. List the modules (14 total)

```bash
thursec list
```

```console
[recon]
  recon.ct_subdomains              Certificate Transparency subdomains  (passive, passive)
  recon.dns                        DNS enumeration (DoH)  (passive, passive)
  recon.nmap                       Nmap port & service scan  (active, scope-gated)
  recon.whois                      Domain registration (RDAP/WHOIS)  (passive, passive)

[vuln]
  vuln.cve_lookup                  CVE lookup (NVD)  (passive, passive)
  vuln.http_methods                HTTP methods & info exposure  (active, scope-gated)
  vuln.nuclei                      Nuclei vulnerability scan  (active, scope-gated)

[deps_secrets]
  deps_secrets.dep_audit           Dependency audit (OSV)  (passive, passive)
  deps_secrets.secret_scan         Local secret scan  (passive, passive)

[config_audit]
  config_audit.cookies             Cookie security flags  (active, scope-gated)
  config_audit.server_configs      Server config linter (nginx/sshd)  (passive, passive)
  config_audit.supabase            Supabase posture audit  (passive, passive)
  config_audit.tls_headers         TLS & HTTP security headers  (active, scope-gated)

[resilience]
  resilience.load_test             Resilience / load test  (intrusive, scope-gated)
```

That's **14 modules**. Note the `(passive, passive)` vs `(active, scope-gated)`
vs `(intrusive, scope-gated)` labels — they drive the gate in the next step.

---

## 2. The scope gate — the differentiator

An `active`/`intrusive` module **refuses** to touch a target that isn't in an
authorized scope file. Watch it get skipped, then run.

```bash
# No scope → SKIPPED
thursec run localhost:8000 -m vuln.http_methods
```

```console
Running 1 module(s) against localhost:8000

  ~ vuln.http_methods: SKIPPED — vuln.http_methods is active; load a scope file (--scope) before running it against 'localhost:8000'.

Summary: CRITICAL 0, HIGH 0, MEDIUM 0, LOW 0, INFO 0
```

```bash
# With an authorizing scope → runs
thursec run localhost:8000 -m vuln.http_methods --scope scope.yaml
```

```console
Scope loaded: ThurSec local demo — authorized by arthur.maciel@raiobeneficios.com, expires 2026-12-31 (2 target pattern(s))
Running 1 module(s) against localhost:8000

  ✓ vuln.http_methods: 1 finding(s), 1 notable

Summary: CRITICAL 0, HIGH 0, MEDIUM 0, LOW 1, INFO 0
```

Staying in-scope is the default; going out-of-scope is an explicit act.

---

## 3. Passive analysis (no scope needed, no packets to any target)

Passive modules read local files or public databases — they never send traffic
to the target, so they run without a scope file.

### Local secret scan (point it at this repo)

```bash
thursec run . -m deps_secrets.secret_scan
```

```console
Running 1 module(s) against .

  ✓ deps_secrets.secret_scan: 4 finding(s), 4 notable

Summary: CRITICAL 1, HIGH 3, MEDIUM 0, LOW 0, INFO 0
```

The hits are the **intentional test fixtures** shipped in the repo (e.g. a PEM
key and AWS key in `tests/test_secret_scan.py`) — proof the detector works:

```
[Critical] Possible Private Key (PEM) in tests/test_secret_scan.py
[High]     Possible AWS Access Key ID in tests/test_secret_scan.py
```

### Dependency audit (OSV)

```bash
thursec run . -m deps_secrets.dep_audit
```

```console
Running 1 module(s) against .

  ✓ deps_secrets.dep_audit: 7 finding(s), 0 notable

Summary: CRITICAL 0, HIGH 0, MEDIUM 0, LOW 0, INFO 7
```

> This module queries the public **OSV** database. With no network, the OSV
> lookups fail gracefully and are reported as handled INFO findings — the run
> still completes.

### Server-config linter (nginx / sshd)

```bash
thursec run /tmp/thursec-demo -m config_audit.server_configs
```

```console
Running 1 module(s) against /tmp/thursec-demo

  ✓ config_audit.server_configs: 4 finding(s), 4 notable

Summary: CRITICAL 1, HIGH 1, MEDIUM 1, LOW 1, INFO 0
```

The four findings map exactly to our insecure `sshd_config`:

```
[Critical] sshd: PermitEmptyPasswords yes in sshd_config   (line 5)
[High]     sshd: PermitRootLogin yes in sshd_config        (line 2)
[Medium]   sshd: PasswordAuthentication yes in sshd_config (line 3)
[Low]      sshd: X11Forwarding yes in sshd_config          (line 4)
```

---

## 4. Module options via `--opt KEY=VALUE`

`--opt` passes a typed option to a module (repeatable; last wins for a repeated
key). Values are coerced: `true`/`false` → bool, integers → int, decimals →
float, everything else stays a string.

`vuln.cve_lookup` takes a `product:version` **target**, or `--opt product=` /
`--opt version=`. It queries the public NVD database (passive — nothing is sent
to any target).

```bash
# Fingerprint as the target:
thursec run nginx:1.18.0 -m vuln.cve_lookup
```

```console
Running 1 module(s) against nginx:1.18.0

  ✓ vuln.cve_lookup: 50 finding(s), 50 notable

Summary: CRITICAL 11, HIGH 22, MEDIUM 16, LOW 1, INFO 0
```

```bash
# Same thing, driven entirely by --opt:
thursec run cve-demo -m vuln.cve_lookup --opt product=openssl --opt version=1.1.1
```

```console
Running 1 module(s) against cve-demo

  ✓ vuln.cve_lookup: 50 finding(s), 50 notable

Summary: CRITICAL 4, HIGH 14, MEDIUM 29, LOW 3, INFO 0
```

**Offline / no product:** if NVD is unreachable, the lookup error is caught and
reported as a handled finding. And with no product at all, you get a single INFO
finding explaining what to pass:

```console
$ thursec run sometarget -m vuln.cve_lookup
  ✓ vuln.cve_lookup: 1 finding(s), 0 notable
Summary: CRITICAL 0, HIGH 0, MEDIUM 0, LOW 0, INFO 1
```

---

## 5. INTRUSIVE module — double barrier + `--opt` (local, tiny, safe)

`resilience.load_test` is `INTRUSIVE`. It passes **two** barriers: the scope
gate **and** an explicit intrusive confirmation. It also *requires* `max_rps`
and is hard-capped on rate (≤200) and duration, with an automatic error-rate
kill-switch. We point it at our **own** local server at a tiny 20 req/s for 3s.

```bash
thursec run http://localhost:8000/ -m resilience.load_test \
  --scope scope.yaml --confirm-intrusive \
  --opt max_rps=20 --opt duration_s=3
```

```console
Scope loaded: ThurSec local demo — authorized by arthur.maciel@raiobeneficios.com, expires 2026-12-31 (2 target pattern(s))
Running 1 module(s) against http://localhost:8000/

  ✓ resilience.load_test: 1 finding(s), 0 notable

Summary: CRITICAL 0, HIGH 0, MEDIUM 0, LOW 0, INFO 1
```

The INFO summary finding carries the latency/error numbers:

```
60 GET requests, 20.0 eff. req/s, error rate 0.0%, latency p50/p90/p99 = 2/2/2 ms
```

> **Use the explicit `http://...` URL form.** With a bare `localhost:8000`,
> load_test defaults to **https** and tries a TLS handshake against the plain
> HTTP server — every request fails. That's actually a good thing to see once:
> the **kill-switch trips** at a 100% error rate and aborts the test early,
> reporting a HIGH "Load test aborted by kill-switch" finding. Either way the
> tool protects the target.

Without `--confirm-intrusive`, an interactive terminal prompts you to re-type the
exact target; a non-interactive run (CI) simply skips the intrusive module with
a clear reason. Scope alone is never enough for an intrusive module.

---

## 6. Memory — `--store`, `diff`, and `dashboard`

Persist runs to a SQLite store, then compare them over time and render an HTML
posture dashboard. We do two runs of the same target, the second adding two more
modules, so the diff shows new findings.

```bash
thursec run localhost:8000 -m vuln.http_methods \
  --scope scope.yaml --store demo.db

thursec run localhost:8000 \
  -m vuln.http_methods -m config_audit.cookies -m config_audit.tls_headers \
  --scope scope.yaml --store demo.db
```

```console
Run #1 persisted to store demo.db
...
Run #2 persisted to store demo.db
```

```bash
thursec diff --store demo.db localhost:8000
```

```console
Diff for localhost:8000 — run #1 (baseline) vs run #2 (latest)

  New (2):
    + [MEDIUM] Could not establish TLS connection  (config_audit.tls_headers / localhost:8000)
    + [LOW] Could not complete GET request  (config_audit.cookies / localhost:8000)

  Resolved (0):
    (none)

  Changed severity (0):
    (none)
```

```bash
thursec dashboard --store demo.db localhost:8000 -o dashboard.html
```

```console
Dashboard written to dashboard.html
```

Open `dashboard.html` in a browser for the posture view (severity breakdown and
run history).

---

## 7. Security awareness (anti-phishing training) — allowlist enforced

`awareness generate` builds **educational** artifacts (a landing page with *no*
credential capture, a training e-mail template that the tool does **not** send,
and per-recipient tracking tokens). It refuses any recipient outside the
allowlist, and requires an explicit authorizer + date.

```bash
# A recipient outside the allowlist → refused, nothing written:
thursec awareness generate --name "Q4 Phishing Drill" \
  --authorized-by "Arthur Maciel" --authorized-on 2026-10-01 \
  --allow raiobeneficios.com \
  --recipient alice@raiobeneficios.com --recipient mallory@gmail.com \
  --base-url "https://training.internal.example/learn" \
  -o /tmp/thursec-demo/awareness_campaign
```

```console
awareness error: recipient(s) outside the allowlist — refusing to generate campaign artifacts: mallory@gmail.com
```

```bash
# All recipients in the allowlist → artifacts generated:
thursec awareness generate --name "Q4 Phishing Drill" \
  --authorized-by "Arthur Maciel" --authorized-on 2026-10-01 \
  --allow raiobeneficios.com \
  --recipient alice@raiobeneficios.com --recipient bob@raiobeneficios.com \
  --base-url "https://training.internal.example/learn" \
  --org-contact "security@raiobeneficios.com" \
  -o /tmp/thursec-demo/awareness_campaign
```

```console
Authorized by Arthur Maciel on 2026-10-01
Allowlist OK · 2 recipient(s) validated
Artifacts written to /tmp/thursec-demo/awareness_campaign/:
  landing_page.html   (educational — NO credential capture)
  email_template.txt  (training template — NOT sent by this tool)
  tokens.csv, tokens.json  (per-recipient tracking tokens)
```

---

## 8. TUI (optional)

A Textual TUI sits on the same primitives. With the `[tui]` extra installed:

```bash
thursec-tui
```

It opens a full-screen terminal app (module list, "Load scope" and "Run"
actions). Quit with `q` or `Ctrl+C`. Nothing to capture here — just show it live.

---

## Optional external tools (nmap / nuclei)

`recon.nmap` and `vuln.nuclei` wrap external binaries. If they aren't installed,
ThurSec doesn't crash — it emits a handled INFO finding telling you how to install
them. Both are **optional**; the rest of the demo needs neither.

```console
$ thursec run localhost -m recon.nmap --scope scope.yaml
  ✓ recon.nmap: 1 finding(s), 0 notable

# [Info] nmap not installed
# The nmap binary was not found on PATH, so the port scan was skipped.
# Recommendation: Install nmap (e.g. 'brew install nmap', 'apt install nmap').
```

```console
$ thursec run localhost:8000 -m vuln.nuclei --scope scope.yaml
  ✓ vuln.nuclei: 1 finding(s), 0 notable   # handled "nuclei not installed" INFO
```

Install them to see real output: `brew install nmap nuclei` (macOS) or your
distro's packages.

---

## 5-minute presentation script

1. **The problem (~45s).** Menu-driven "all-in-one" security toolkits shell out
   with no timeouts, no scope control, and no reporting. It's too easy to point
   them at the wrong host. Run `thursec list` — 14 self-describing modules, each
   labelled passive / active / intrusive.
2. **The ethical boundary (~60s).** Run step 2: the same `vuln.http_methods`
   command is **SKIPPED** without a scope, then **runs** once `scope.yaml`
   authorizes the host. Staying in-scope is the default. Mention the second
   barrier for intrusive work (`--confirm-intrusive`).
3. **Live demo (~2.5min).**
   - Passive wins with no scope: `secret_scan` (finds the planted test secrets)
     and `server_configs` (flags the insecure `sshd_config`) — steps 3.
   - `--opt` in action: `cve_lookup` on `nginx:1.18.0` — step 4.
   - Intrusive but safe: the hard-capped, 3-second, local `load_test` with its
     latency summary and kill-switch — step 5.
   - Memory: two stored runs, then `diff` and the HTML `dashboard` — step 6.
4. **The close (~45s).** `awareness` shows the project's stance made concrete:
   training artifacts with an **enforced allowlist**, no credential capture, and
   no e-mail actually sent — step 7. ThurSec keeps the convenience of an
   all-in-one toolkit and fixes the engineering: scope gates, hard caps, handled
   failures, and structured, shareable output.

---

## Cleanup

```bash
# Stop the local target
pkill -f "http.server 8000"

# Remove demo artifacts
rm -f demo.db dashboard.html
rm -rf /tmp/thursec-demo
rm -f scope.yaml           # (git-ignored anyway)

# Optional: drop the virtualenv
deactivate 2>/dev/null; rm -rf .venv
```
