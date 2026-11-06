"""CVE-2026-109518 — APT package-verification bypass (TOCTOU hard-link reuse).

An on-path attacker who can manipulate HTTP traffic between an APT client and an
archive server can get an unverified package installed and run code as root.
Affects apt on Debian, Ubuntu and derivatives; FreeBSD and non-apt systems are
not affected. Only exploitable when APT retries downloads (Acquire::Retries != 0,
the default from Debian 12 / Ubuntu 22.04). Verdict is driven by the apt version.
"""

from cvelib import installed_version, version_less_than

CVE_ID = "CVE-2026-109518"

# Fixed apt versions, by distro + release (keyed by VERSION_ID). Sources:
#   Debian: https://security-tracker.debian.org/tracker/CVE-2026-109518
#   Ubuntu: https://ubuntu.com/security/CVE-2026-109518  (USN-8996-1)
APT_FIXED = {
    "debian": {
        "11": "2.2.5",      # bullseye (LTS)
        "12": "2.6.2",      # bookworm
        "13": "3.0.4",      # trixie
    },
    "ubuntu": {
        "14.04": "1.0.1ubuntu2.24+esm4",  # ESM (Ubuntu Pro)
        "16.04": "1.2.36+esm1",           # ESM
        "18.04": "1.6.19+esm1",           # ESM
        "20.04": "2.0.12+esm1",           # ESM
        "22.04": "2.4.15ubuntu0.1",
        "24.04": "2.8.4ubuntu0.1",
        "26.04": "3.2.1ubuntu0.1",
        "26.10": "3.3.3ubuntu0.1",
    },
}


def cve_check(run, osinfo):
    family = osinfo["family"]
    if family not in ("ubuntu", "debian"):   # detect_os maps Debian -> "ubuntu" too
        return {"status": "not_applicable",
                "details": [{"note": f"{osinfo.get('os', '?')} does not use APT"}]}

    osname = osinfo.get("os", "").lower()
    distro = "ubuntu" if "ubuntu" in osname else "debian" if "debian" in osname else None

    inst = installed_version(run, family, "apt")
    if inst is None:
        return {"status": "not_applicable", "details": [{"note": "apt not installed"}]}

    # Exposure context: parse `apt-config dump Acquire::Retries` (Acquire::Retries "3";)
    _, rconf, _ = run("apt-config dump Acquire::Retries 2>/dev/null")
    parts = rconf.split('"')
    retries = parts[1] if len(parts) >= 2 else "unset (release default applies)"

    rel = osinfo.get("version", "")
    advisory = ("https://security-tracker.debian.org/tracker/CVE-2026-109518"
                if distro == "debian"
                else "https://ubuntu.com/security/CVE-2026-109518")
    base = {"apt_installed": inst, "acquire_retries": retries, "advisory": advisory}

    fixed = APT_FIXED.get(distro, {}).get(rel)
    if fixed is None:
        return {"status": "review",
                "details": [{**base, "note": f"no fixed apt version listed for "
                                             f"{distro or 'this distro'} {rel}"}]}

    vulnerable = version_less_than(run, family, inst, fixed)
    return {"status": "vulnerable" if vulnerable else "ok",
            "details": [{**base, "fixed_version": fixed}]}


def mitigation_check(run, osinfo):
    # The flaw is only exploitable when APT retries downloads, so
    # Acquire::Retries=0 removes the precondition (not a substitute for the patch).
    family = osinfo["family"]
    if family not in ("ubuntu", "debian"):
        return {"status": "not_applicable", "details": [{"note": "no APT on this OS"}]}

    _, rconf, _ = run("apt-config dump Acquire::Retries 2>/dev/null")
    parts = rconf.split('"')
    retries = parts[1] if len(parts) >= 2 else None
    info = {"acquire_retries": retries if retries is not None else "unset"}

    if retries == "0":
        return {"status": "mitigated",
                "details": [{**info, "note": "Acquire::Retries=0 — retry path "
                                             "disabled; not a substitute for the patch"}]}
    return {"status": "not_mitigated",
            "details": [{**info, "note": "download retries enabled; set "
                                         "Acquire::Retries=0 or use HTTPS mirrors "
                                         "until apt is patched"}]}


REMEDIATION = """# The fix

Upgrade the **apt** package to the fixed version for your release and confirm it.
The fix is in the standard security pocket for supported releases; older releases
need Ubuntu Pro / Debian LTS (ESM) coverage.

Debian / Ubuntu:

```
sudo apt update
sudo apt install --only-upgrade apt -o Acquire::Retries=0
apt-get -v | head -n1        # confirm apt is at or above the fixed version
```

Fixed apt versions:

- Debian 12 (bookworm): 2.6.2 - Debian 13 (trixie): 3.0.4 - Debian 11 (bullseye, LTS): 2.2.5
- Ubuntu 22.04: 2.4.15ubuntu0.1 - 24.04: 2.8.4ubuntu0.1 - 26.04: 3.2.1ubuntu0.1 - 26.10: 3.3.3ubuntu0.1
- Ubuntu 20.04 and older: via Ubuntu Pro (ESM), e.g. 20.04 -> 2.0.12+esm1
- Advisories: https://ubuntu.com/security/CVE-2026-109518 (USN-8996-1) and
  https://security-tracker.debian.org/tracker/CVE-2026-109518

# Interim mitigation (reduces exposure, not a fix)

The attack only works when APT retries a failed download. Until apt is patched:

```
echo 'Acquire::Retries "0";' | sudo tee /etc/apt/apt.conf.d/99-cve-2026-109518
```

Remove that file after patching. Serving your mirrors over **HTTPS** also defeats
the on-path package swap. Neither step fixes the underlying apt bug.

# Not affected

FreeBSD and other systems that don't use APT are not affected - no action needed.
"""