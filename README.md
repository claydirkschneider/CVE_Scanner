# cve_scan.py — Fleet CVE audit over SSH

Sweeps a subnet, checks each IP's SSH port, logs in with a password, detects the
OS and version, runs a per-CVE check, and records **every IP in the range** (not
just the ones it reached) to JSON and CSV.

Built for auditing **our own** mixed FreeBSD + Ubuntu servers.

---

## 1. Requirements

- Python 3.9+
- [`paramiko`](https://www.paramiko.org/) for SSH

```bash
pip install -r requirements.txt
```

## 2. Quick start

The password is read from an environment variable so it never lands in your
shell history or the process list. If the variable is unset, the script prompts
for it.

```bash
export SSH_PASSWORD='your-password'
python3 cve_scan.py --subnet 10.0.0.0/24 --username admin --output audit
```

That writes `audit.json` and `audit.csv` in the current directory.

### Common options

| Flag | Default | Meaning |
|------|---------|---------|
| `--subnet` | *(required)* | CIDR, single IP, or comma list. Repeatable. e.g. `--subnet 10.0.0.0/24 --subnet 10.1.0.5` |
| `--username`, `-u` | *(required)* | SSH username (same for all hosts) |
| `--password-env` | `SSH_PASSWORD` | Name of the env var holding the password |
| `--port`, `-p` | `22` | SSH/port to test and connect on |
| `--workers`, `-w` | `20` | Concurrent hosts |
| `--timeout`, `-t` | `8` | Per-connection / port-check timeout (seconds) |
| `--output`, `-o` | `cve_scan_results` | Output file prefix |
| `--mitigation-check` | *(off)* | Also run the `mitigation_check()` hook per host (workaround/exposure posture, independent of patch status) |

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

## 4. Per-CVE checks (how the script is kept generic)

The script never hardcodes a single CVE's logic into its plumbing. All the
CVE-specific logic lives in **one function, `cve_check(run, osinfo)`**, plus two
fixed-version tables (`UBUNTU_FIXED`, `FREEBSD_FIXED`) near the top. To audit a
different CVE you replace that function (and/or fill the tables) — nothing else.

Simple "package below version X is vulnerable" cases don't even need new code:
just add entries to the right table. Anything more involved (kernel checks,
config-dependent mitigations, multi-package logic) goes in `cve_check`.

The currently shipped check is **CVE-2026-98432** (Linux kernel IPv4 TCP
use-after-free). FreeBSD is reported `not_applicable` because it's a Linux-kernel
bug; Ubuntu hosts are checked against `UBUNTU_FIXED`, which you populate from
<https://ubuntu.com/security/CVE-2026-98432>.

### Optional: mitigation check

Some CVEs have a workaround you can apply while a vendor patch is pending (a
sysctl, an nftables rule, a disabled feature). That's **separate from patch
status** — a workaround lowers exposure but doesn't mean the bug is gone. There's
a second, optional hook for this, `mitigation_check(run, osinfo)`, with the exact
same contract as `cve_check`. It runs only with `--mitigation-check`, and its
result is recorded per host (`mitigation` in the JSON; two extra columns in the
CSV) alongside — never instead of — the CVE verdict.

Like `cve_check`, it's generic: replace its body per CVE. The shipped version
reports MPTCP exposure (the CVE-2026-98432 workaround), with statuses
`mitigated` / `not_mitigated` / `not_applicable`. Keep your `vulnerable`/`ok`
verdict driven by the kernel version, not by the mitigation state.

---

## 5. Executive report — `make_report.py`

Turns a scan's JSON into a one-page HTML report titled with the CVE, aimed at a
security exec. Intended to be run **once the fixes are in**, to show the CVE is
remediated across the fleet.

```bash
python3 make_report.py audit.json --org "Your Team" --prepared-by "Your Name"
```

Writes `audit_report.html` next to the input (override with `-o`). Open it in a
browser, or print to PDF to share.

| Flag | Meaning |
|------|---------|
| `json` | JSON file from `cve_scan.py` (required, positional) |
| `--output`, `-o` | output HTML path (default `<input>_report.html`) |
| `--cve` | override the title (otherwise taken from the data) |
| `--org` | organization name shown in the header |
| `--prepared-by` | byline shown in the header |

The report leads with a verdict banner: green **REMEDIATED** when no audited host
is vulnerable, red **NOT REMEDIATED** with a count when any still is, amber when
nothing is vulnerable but some hosts are `review`/`error`. Below it: headline
tiles, an OS breakdown, a status legend, and a per-host table (worst first) with
the version evidence behind each verdict. Only hosts that were logged into are
assessed — unreachable IPs count toward scope but get no CVE verdict, so a true
all-clear means the fleet is both reachable and `ok`/`not_applicable`.

---

## 6. SPEC: generating a `cve_check` with an AI assistant

> Paste this whole section (section 6) into an AI chat along with the CVE you
> want. Ask it to **return only a Python `cve_check` function** (and, if useful,
> values for the fixed-version tables and the `CVE_ID` constant). Do **not** let
> it rewrite the rest of `cve_scan.py` — you only swap this one function.

**Task for the AI:** Write a Python function `cve_check(run, osinfo)` that decides
whether a remote host is affected by a given CVE, using only the interface below.
Return nothing else except, optionally, the table/constant values described.

### The interface you may use

- `run(cmd, timeout=15) -> (exit_code: int, stdout: str, stderr: str)`
  Runs a shell command **on the remote host** over SSH. `stdout`/`stderr` are
  already stripped. Use `2>/dev/null` and `|| true` to keep commands quiet.
  Commands must be **read-only** — never modify the host.

- `osinfo -> dict` with:
  - `family`: `"ubuntu"`, `"debian"`, `"linux"` (other Linux distro id), or `"freebsd"`
  - `os`: human-readable OS name (e.g. `"Ubuntu 22.04.4 LTS"`, `"FreeBSD"`)
  - `version`: Ubuntu/Debian `VERSION_ID` (e.g. `"22.04"`); on FreeBSD the
    `freebsd-version` string (e.g. `"13.2-RELEASE-p5"`)

- Two helpers (already defined in the script) you may call:
  - `installed_version(run, family, package) -> str | None`
    Installed version of a package. On Ubuntu/Debian uses `dpkg-query`; on
    FreeBSD uses `pkg query`. Pass `package="__base__"` on FreeBSD to get the
    base-system version from `freebsd-version`.
  - `version_less_than(run, family, installed, fixed) -> bool`
    True if `installed` < `fixed`, compared with the host's **native** tooling
    (`dpkg --compare-versions` on Ubuntu/Debian, `pkg version -t` on FreeBSD).
    Always use this instead of comparing version strings yourself.

### What the function must return

A dict:

```python
{"status": "<status>", "details": [ ... ]}   # details: any JSON-serializable list
```

`status` must be one of:

| status | use it when |
|--------|-------------|
| `vulnerable` | the host is affected and unpatched |
| `ok` | the host is patched / not affected by version |
| `not_applicable` | this OS/family can't be affected by this CVE at all |
| `review` | you can't confirm (unknown fixed version, unexpected output) — do **not** guess `ok` |
| `error` | something went wrong gathering data |

Only `vulnerable` is counted in the final tally, so reserve it for confirmed cases
and use `review` when unsure.

### Rules

1. Branch on `osinfo["family"]` first. If a family can't be affected, return
   `not_applicable` immediately (e.g. a Linux-only kernel bug → FreeBSD is
   `not_applicable`).
2. Prefer the native helpers over hand-rolled version math.
3. Keep every `run()` command **read-only** and portable; guard with `2>/dev/null`.
4. Never raise for expected conditions; return `review`/`error` instead. (The
   caller catches exceptions and records `error`, but don't rely on that.)
5. Put the evidence you used (versions found, flags checked) in `details` so the
   output is auditable.
6. If the CVE is a simple package/version cutoff, you may instead just give table
   entries for `UBUNTU_FIXED` / `FREEBSD_FIXED` and leave the default logic.

### Worked example (the shipped CVE-2026-98432 check, abridged)

```python
def cve_check(run, osinfo):
    """Linux kernel IPv4 TCP use-after-free. Linux-only; FreeBSD not affected."""
    family = osinfo["family"]
    if family not in ("ubuntu", "debian", "linux"):
        return {"status": "not_applicable",
                "details": [{"note": f"{osinfo.get('os')} is not Linux"}]}

    _, krel, _ = run("uname -r")  # running kernel, e.g. 5.15.0-125-generic
    code, pkgver, _ = run(f"dpkg-query -W -f='${{Version}}' linux-image-{krel} 2>/dev/null")
    pkgver = pkgver if (code == 0 and pkgver) else None

    fixed = "5.15.0-140.150"  # from the distro's CVE tracker, per release/flavor
    if not pkgver:
        return {"status": "review", "details": [{"kernel": krel, "note": "pkg version unknown"}]}

    is_vuln = version_less_than(run, family, pkgver, fixed)
    return {"status": "vulnerable" if is_vuln else "ok",
            "details": [{"kernel": krel, "installed": pkgver, "fixed": fixed}]}
```

Where to paste the result: replace the function under the banner
`#### CVE CHECK — PASTE / REPLACE THIS FUNCTION PER CVE ####` in `cve_scan.py`,
and update `CVE_ID` at the top so the output labels the right CVE.

**Optional mitigation hook.** The same contract and the same helpers apply to
`mitigation_check(run, osinfo)` (banner `#### MITIGATION CHECK ####`), which runs
only under `--mitigation-check` and reports workaround/exposure posture rather
than patch status. Suggested statuses: `mitigated`, `not_mitigated`,
`not_applicable`, `review`, `error`. If you want an AI to write it too, ask for a
`mitigation_check` with these statuses — everything else above is identical.

---

## 7. Operational notes & safety

- **Authorized use only.** This logs into hosts and runs commands. Run it only
  against servers you're responsible for.
- **Host keys:** the script uses `AutoAddPolicy`, so it accepts unknown host keys
  on first contact — convenient for a sweep, but it means no protection against a
  man-in-the-middle on that first connection. If you maintain a `known_hosts` for
  the fleet, switch the policy to reject unknown keys.
- **Password auth** is used because that's the environment here. Key-based auth is
  stronger; moving to it is worth doing when you can.
- **The password** is only read from the env var (or an interactive prompt) and is
  never written to the output files.
- `review` is not `ok`. A host that can't be confirmed patched is listed for
  manual follow-up on purpose.
- **Don't commit scan outputs.** `audit.json` / `audit.csv` / `*_report.html`
  contain your real host inventory — IPs, OS/versions, which hosts are
  vulnerable. The included `.gitignore` keeps them out of the repo; the scripts
  themselves hold no hosts, credentials, or secrets.