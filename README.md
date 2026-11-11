# cve_scan.py — Fleet CVE audit over SSH

Sweeps a subnet, checks each IP's SSH port, logs in with a password, detects the
OS and version, runs a CVE check, and records **every IP in the range** (not just
the ones it reached) to JSON and CSV. A companion script turns that into an
executive HTML report.

Built for auditing **our own** mixed FreeBSD + Ubuntu/Debian servers.

Each CVE is a self-contained definition file in `cves/`; the scanner is
CVE-agnostic and loads one by name with `--cve`. **Adding a CVE means adding a
file — you never edit the scanner.**

```
cve_scan.py          the scanner (CVE-agnostic)
make_report.py       JSON -> executive HTML report
cvelib.py            shared helpers + the CVE loader
cves/                one file per CVE:
  CVE_2026_98432.py    Linux kernel IPv4 TCP use-after-free
  CVE_2026_109518.py   APT package-verification bypass
requirements.txt
.gitignore
```

---

## 1. Requirements

- Python 3.9+
- [`paramiko`](https://www.paramiko.org/) for SSH

```bash
pip install -r requirements.txt          # FreeBSD: doas pkg install py311-paramiko
```

## 2. Quick start

The password is read from an environment variable so it never lands in your
shell history or the process list. If the variable is unset, the script prompts
for it.

```bash
export SSH_PASSWORD='your-password'
python3 cve_scan.py --cve CVE-2026-109518 --subnet 10.0.0.0/24 --username admin --output audit
```

That writes `audit_CVE-2026-109518.json`, `.csv`, and `.remediation.md` in the
current directory — the CVE is always part of the filename, so scans for
different CVEs never collide. `--cve CVE-2026-109518` loads
`cves/CVE_2026_109518.py`. With no `--output`, files are named automatically from the CVE, subnet and
run time (`CVE-2026-109518_10.0.0.0-24_20261111-125900.json`), so every run is its own version.

### Common options

| Flag | Default | Meaning |
|------|---------|---------|
| `--cve` | *(required)* | CVE ID to check, e.g. `CVE-2026-109518`. Loads `cves/CVE_2026_109518.py` |
| `--cve-dir` | `cves/` next to the script | Directory of CVE definition files |
| `--subnet` | *(required)* | CIDR, single IP, or comma list. Repeatable. e.g. `--subnet 10.0.0.0/24 --subnet 10.1.0.5` |
| `--username`, `-u` | *(required unless `--creds-file`)* | SSH username (same for all hosts) |
| `--creds-file` | | JSON list of `{"username","password"}` pairs tried in order per host until one logs in (file must be `chmod 600`; replaces `--username`) |
| `--max-attempts` | `3` | Max credential pairs tried per host (avoids lockouts / fail2ban / CSF LFD) |
| `--password-env` | `SSH_PASSWORD` | Name of the env var holding the password |
| `--port`, `-p` | `22` | Port to test and connect on |
| `--workers`, `-w` | `20` | Concurrent hosts |
| `--timeout`, `-t` | `8` | Per-connection / port-check timeout (seconds) |
| `--output`, `-o` | *(CVE ID)* | Output prefix; the CVE ID is always appended (`-o audit` → `audit_CVE-XXXX.json`). Default is `<CVE>_<subnet>_<YYYYMMDD-HHMMSS>` |
| `--mitigation-check` | *(off)* | Also run the definition's `mitigation_check()` per host (workaround/exposure posture, independent of patch status) |

## 3. What you get back

**On screen** (quiet): only hosts it logged into, plus genuine errors. The common
`port_closed` case is silent on screen but still saved to the files. A summary at
the end tallies every state.

**In the files**, one row/record per IP in the whole range, with a `state`:

| state | meaning |
|-------|---------|
| `logged_in` | Logged in; has OS, version, and CVE result |
| `auth_failed` | Port open, SSH up, password rejected |
| `port_closed` | Nothing listening on the port |
| `ssh_error` | Port open but SSH handshake failed (see `error`) |
| `info_error` | Logged in but couldn't gather info |

To get just the hosts it reached: `grep logged_in audit.csv`, or filter the JSON
on `"state": "logged_in"`.

CVE results use these statuses: `vulnerable`, `ok`, `not_applicable` (this OS
isn't affected), `review` (couldn't confirm — check manually, **not** a clean
bill of health), or `error`. Only `vulnerable` counts in the final tally.

## 4. CVE definition files (how a CVE is added)

A CVE lives in `cves/CVE_YYYY_NNNNN.py` (the ID with dashes turned to
underscores). The scanner imports it by `--cve` and calls into it; the scanner,
`cvelib.py`, and `make_report.py` never change. A definition provides:

| name | required | purpose |
|------|----------|---------|
| `CVE_ID` | yes | e.g. `"CVE-2026-109518"` — labels the output and report |
| `cve_check(run, osinfo)` | yes | returns `{"status", "details"}` — the verdict |
| `mitigation_check(run, osinfo)` | no | workaround/exposure posture (used by `--mitigation-check`) |
| `REMEDIATION` | no | markdown string with the known fix (written to the sidecar for the report) |

`cve_check` and `mitigation_check` share one contract:

- `run(cmd, timeout=15) -> (exit_code, stdout, stderr)` runs a **read-only** shell
  command on the host. `stdout`/`stderr` are stripped.
- `osinfo -> {"family": "ubuntu"|"debian"|"freebsd"|..., "os": str, "version": str}`
  (`version` is `VERSION_ID` on Linux, the `freebsd-version` string on FreeBSD).
- Return `{"status": ..., "details": [...]}`. `cve_check` status is one of
  `vulnerable` / `ok` / `not_applicable` / `review` / `error`;
  `mitigation_check` uses `mitigated` / `not_mitigated` / `not_applicable` /
  `review` / `error`. Only `vulnerable` counts in the tally.

Two helpers live in `cvelib.py` and are imported by the definitions:

- `installed_version(run, family, package)` — installed version via `dpkg-query`
  (Debian/Ubuntu) or `pkg query` (FreeBSD); `package="__base__"` gives the FreeBSD
  base version.
- `version_less_than(run, family, installed, fixed)` — compares with the host's
  **native** tooling (`dpkg --compare-versions`, `pkg version -t`). Use it instead
  of comparing strings yourself.

**The mitigation check** is separate from patch status — a workaround lowers
exposure but doesn't mean the bug is gone. It runs only with `--mitigation-check`,
and its result is recorded per host (`mitigation` in the JSON; two extra CSV
columns) **alongside, never instead of** the CVE verdict. Keep `vulnerable`/`ok`
driven by the package/kernel version.

The two shipped definitions are good templates: `CVE_2026_109518.py` (an apt
package-version check; FreeBSD `not_applicable`) and `CVE_2026_98432.py` (a kernel
check with per-release/flavor tables and an MPTCP mitigation; FreeBSD
`not_applicable` for a different reason). To write a new one by hand or with an
AI, see section 6.

---

## 5. Executive report — `make_report.py`

Turns a scan's JSON into a one-page HTML report titled with the CVE, aimed at a
security exec. Intended to be run **once the fixes are in**, to show the CVE is
remediated across the fleet.

```bash
python3 make_report.py audit_CVE-2026-109518.json --org "Your Team" --prepared-by "Your Name"
```

Writes `audit_CVE-2026-109518_report.html` next to the input (override with
`-o`). Open it in a browser, or print to PDF to share. The CVE-named sidecar the
scanner wrote (`audit_CVE-2026-109518.remediation.md`) is auto-detected.

| Flag | Meaning |
|------|---------|
| `json` | JSON file from `cve_scan.py` (required, positional) |
| `--output`, `-o` | output HTML path (default `<input>_report.html`) |
| `--cve` | override the title (otherwise taken from the data) |
| `--org` | organization name shown in the header |
| `--prepared-by` | byline shown in the header |
| `--fix` / `--fix-file` | remediation text / file (see below) |

The report leads with a verdict banner: green **REMEDIATED** when no audited host
is vulnerable, red **NOT REMEDIATED** with a count when any still is, amber when
nothing is vulnerable but some hosts are `review`/`error`. Below it: headline
tiles, an OS breakdown, a status legend, and a per-host table (worst first) with
the version evidence behind each verdict. Only hosts that were logged into are
assessed — unreachable IPs count toward scope but get no CVE verdict, so a true
all-clear means the fleet is both reachable and `ok`/`not_applicable`.

### The known-fix section

The report renders a **"Known fix & remediation"** section from markdown, so the
exec sees what the fix is, not just the status. The text is resolved in this
order:

1. `--fix "inline text"`
2. `--fix-file path.md`
3. `<input>.remediation.md` — the sidecar the scanner writes from the CVE
   definition's `REMEDIATION` (auto-detected; nothing to pass)
4. a generic `remediation.md` next to the JSON

So in the normal flow you pass nothing: the scanner emits `audit.remediation.md`
from the definition and the report picks it up. A small markdown subset is
rendered (`#`/`##`/`###` headings, `-`/`*` bullets, ``` fenced code blocks ```,
and links). If none is found the section is simply omitted.

Because the remediation lives inside each `cves/<CVE>.py`, you update it there —
not in a separate file. The generated `*.remediation.md` sidecars are gitignored;
the definition files are what you commit.

---

## 6. Writing a CVE definition (by hand or with an AI)

> To have an AI write one, paste this whole section into a chat along with the
> target CVE and ask for **one complete file**: the contents of
> `cves/CVE_YYYY_NNNNN.py`. You save that file into `cves/` and run
> `--cve CVE-YYYY-NNNNN` — nothing else in the project changes. Do not ask it to
> edit `cve_scan.py`.

**Task for the AI:** Write the complete contents of a CVE definition module for
the given CVE. The file must define `CVE_ID` and `cve_check(run, osinfo)`, and
should also define `mitigation_check(run, osinfo)` (if the CVE has a workaround)
and a `REMEDIATION` markdown string. Import helpers from `cvelib`.

### The interface you may use

- `run(cmd, timeout=15) -> (exit_code, stdout, stderr)` — runs a **read-only**
  shell command on the host; output is stripped. Guard with `2>/dev/null`.
- `osinfo -> dict`: `family` (`"ubuntu"`, `"debian"`, `"linux"`, `"freebsd"`),
  `os` (e.g. `"Ubuntu 22.04.4 LTS"`), `version` (`VERSION_ID`, or the
  `freebsd-version` string on FreeBSD). Note: Debian hosts arrive with
  `family == "ubuntu"`; tell Debian from Ubuntu via the `os` string if needed.
- From `cvelib`: `installed_version(run, family, package)` and
  `version_less_than(run, family, installed, fixed)` — always use the latter
  rather than comparing version strings yourself.

### Return contract

`cve_check` returns `{"status": <s>, "details": [ ... ]}` where `<s>` is:

| status | use it when |
|--------|-------------|
| `vulnerable` | affected and unpatched |
| `ok` | patched / not affected by version |
| `not_applicable` | this OS can't be affected at all |
| `review` | can't confirm (unknown fixed version, odd output) — **never** guess `ok` |
| `error` | data gathering failed |

`mitigation_check` uses `mitigated` / `not_mitigated` / `not_applicable` /
`review` / `error`.

### Rules

1. Branch on `osinfo["family"]` first; return `not_applicable` for families the
   CVE can't touch (e.g. FreeBSD for an apt or Linux-kernel CVE).
2. Use the native helpers; keep every `run()` command read-only and portable.
3. Read kernel/sysctl knobs from `/proc` rather than calling `sysctl`/`ss` by
   name — those live in `/usr/sbin`, which isn't always on a non-login SSH PATH.
4. Never guess `ok`: when there's no confirmed fixed version for a release,
   return `review`.
5. Put the evidence used (versions, flags) in `details` so the output is auditable.
6. `REMEDIATION`: real fix first (fixed package/version + how to apply, per OS,
   with the vendor advisory link), then any interim mitigation clearly labelled
   **not a fix**, then a "Not affected" line per unaffected OS family. State only
   what the advisory says — **don't invent fixed versions**; if a distro's fix is
   pending, say so and link its tracker. No host-specific data (the file is
   committed). Use only the markdown subset the report renders (see section 5).

### Worked example — a complete definition file

```python
"""CVE-YYYY-NNNNN — <one-line summary>."""
from cvelib import installed_version, version_less_than

CVE_ID = "CVE-YYYY-NNNNN"

FIXED = {            # keyed by VERSION_ID
    "22.04": "1.2.3-0ubuntu0.1",
    "24.04": "1.4.5-0ubuntu0.1",
}

def cve_check(run, osinfo):
    family = osinfo["family"]
    if family not in ("ubuntu", "debian"):
        return {"status": "not_applicable",
                "details": [{"note": f"{osinfo.get('os')} not affected"}]}
    inst = installed_version(run, family, "SOME_PACKAGE")
    if inst is None:
        return {"status": "not_applicable", "details": [{"note": "package not installed"}]}
    fixed = FIXED.get(osinfo.get("version", ""))
    if fixed is None:
        return {"status": "review",
                "details": [{"installed": inst, "note": "no fixed version for this release"}]}
    vuln = version_less_than(run, family, inst, fixed)
    return {"status": "vulnerable" if vuln else "ok",
            "details": [{"installed": inst, "fixed": fixed}]}

# Optional: def mitigation_check(run, osinfo): ...

REMEDIATION = """# The fix

<fixed package/version + how to apply, per OS, with the advisory link>

# Not affected

FreeBSD and other systems without SOME_PACKAGE are not affected.
"""
```

Save it as `cves/CVE_YYYY_NNNNN.py`. That's the whole deliverable.

---

## 7. Operational notes & safety

- **Authorized use only.** This logs into hosts and runs commands. Run it only
  against servers you're responsible for.
- **Host keys:** the scanner uses `AutoAddPolicy`, so it accepts unknown host keys
  on first contact — convenient for a sweep, but no protection against a
  man-in-the-middle on that first connection. If you maintain a `known_hosts` for
  the fleet, switch the policy to reject unknown keys.
- **Password auth** is used because that's the environment here. Key-based auth is
  stronger; move to it when you can.
- **The password** is only read from the env var (or an interactive prompt) and is
  never written to the output files.
- `review` is not `ok`. A host that can't be confirmed patched is listed for
  manual follow-up on purpose.
- **Commit the definitions, not the outputs.** `cves/*.py`, the scripts, and this
  README are tracked. `audit.json` / `audit.csv` / `*_report.html` /
  `*.remediation.md` contain or derive from real host inventory and are gitignored.
  The scripts and definitions themselves hold no hosts, credentials, or secrets.

## Multiple credentials

```bash
cat > creds.json <<'EOF'
[{"username": "operator", "password": "..."}, {"username": "admin", "password": "..."}]
EOF
chmod 600 creds.json
python3 cve_scan.py --cve CVE-2026-109518 --subnet 10.0.0.0/24 --creds-file creds.json
```

Pairs are tried in order per host; the first that logs in wins and its username is
recorded (`username` in JSON/CSV, never the password). The scanner refuses a creds
file readable by others. `creds*` is gitignored. Keep `--max-attempts` low to avoid
locking accounts or tripping fail2ban/LFD on your own servers.
