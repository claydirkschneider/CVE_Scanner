"""CVE-2026-119618 - Apache HTTP Server mod_http2: heap corruption / RCE in assign_headers().

Race condition (CWE-362) in mod_http2's assign_headers() that can lead to remote
code execution. Per the CVE record (CNA: Apache), affected are Apache HTTP Server
2.4.55 through 2.4.70, and GitHub mod_h2 2.0.8 through 2.0.42. Upstream fix: 2.4.71.
Severity text from the CNA: critical.

Sources:
  CVE record:  https://www.cve.org/CVERecord?id=CVE-2026-119618
  Apache:      https://httpd.apache.org/security/vulnerabilities_24.html
  Debian:      https://security-tracker.debian.org/tracker/CVE-2026-119618 (DSA-6620-1)

Verdict logic:
  * apache not installed                      -> not_applicable
  * upstream version outside 2.4.55-2.4.70    -> ok (not in the affected range)
  * Debian 13 (trixie)                        -> compare to the fixed package version
  * FreeBSD apache*  (pkg, else httpd -v)    -> ports track upstream: compare to 2.4.71
  * Debian 12/11, Ubuntu (in range), others   -> review: no confirmed fixed package
    version yet (distros backport, so upstream version alone can't prove "patched").
Fill UBUNTU_FIXED / DEBIAN_FIXED as advisories are published and re-run.
"""

import re

from cvelib import installed_version, version_less_than

CVE_ID = "CVE-2026-119618"

AFFECTED_FROM = (2, 4, 55)
AFFECTED_TO = (2, 4, 70)          # inclusive; 2.4.71 is the upstream fix
UPSTREAM_FIXED = "2.4.71"

# Fixed apache2 package versions by release (VERSION_ID). Only list what a
# distro has actually published; anything else falls through to "review".
DEBIAN_FIXED = {
    "13": "2.4.71-1~deb13u1",     # trixie (DSA-6620-1)
    # 12 (bookworm): tracker did not show a confirmed fix when this was written.
    # 11 (bullseye LTS): not tracked yet.
}
UBUNTU_FIXED = {
    # Ubuntu had not published a page for this CVE when this was written.
}

ADVISORY = {
    "debian": "https://security-tracker.debian.org/tracker/CVE-2026-119618",
    "ubuntu": "https://ubuntu.com/security/CVE-2026-119618",
    "upstream": "https://httpd.apache.org/security/vulnerabilities_24.html",
}


def _upstream(ver: str):
    """'1:2.4.58-1ubuntu8.6' / '2.4.66_1' -> (2, 4, 58); None if unparseable."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", ver or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _in_range(up) -> bool:
    return AFFECTED_FROM <= up <= AFFECTED_TO


def _find_apache(run, osinfo):
    """-> (package, installed_version) or (None, None)."""
    family = osinfo["family"]
    if family == "freebsd":
        # 1) pkg: any apache* package (apache24, apache22, ...). Output: "name version".
        _, out, _ = run("pkg query -x '%n %v' '^apache[0-9]'")
        pkgs = [l.split(None, 1) for l in out.splitlines() if len(l.split(None, 1)) == 2]
        if pkgs:
            pkgs.sort(key=lambda nv: nv[0] != "apache24")   # prefer apache24
            return pkgs[0][0], pkgs[0][1]
        # 2) pkg missing/broken or Apache built outside pkg: ask the binary.
        for binary in ("/usr/local/sbin/httpd", "/usr/local/sbin/apachectl"):
            _, vout, _ = run(f"{binary} -v")
            m = re.search(r"Apache/(\d+\.\d+\.\d+)", vout)
            if m:
                return f"httpd (not from pkg: {binary})", m.group(1)
        return (None, None)
    if family in ("ubuntu", "debian"):
        v = installed_version(run, family, "apache2")
        return ("apache2", v) if v else (None, None)
    return (None, None)


def cve_check(run, osinfo):
    family = osinfo["family"]
    if family not in ("ubuntu", "debian", "freebsd"):
        return {"status": "review",
                "details": [{"note": f"no check for OS family '{family}'; see "
                                     f"{ADVISORY['upstream']}"}]}

    pkg, inst = _find_apache(run, osinfo)
    if inst is None:
        return {"status": "not_applicable",
                "details": [{"note": "Apache HTTP Server package not installed"}]}

    up = _upstream(inst)
    base = {"package": pkg, "installed": inst,
            "affected_range": "2.4.55-2.4.70", "upstream_fixed": UPSTREAM_FIXED}
    if up is None:
        return {"status": "review",
                "details": [{**base, "note": "could not parse the Apache version"}]}

    osname = osinfo.get("os", "").lower()
    distro = "ubuntu" if "ubuntu" in osname else "debian" if "debian" in osname else None
    rel = osinfo.get("version", "")
    advisory = ADVISORY.get(distro or "upstream")
    base["advisory"] = advisory

    if not _in_range(up) and up < AFFECTED_FROM:
        return {"status": "ok",
                "details": [{**base, "note": "version predates the affected range "
                                             "(2.4.55+); not affected"}]}

    if family == "freebsd":
        # Ports follow upstream releases: anything below 2.4.71 inside the range is affected.
        if up > AFFECTED_TO:
            return {"status": "ok", "details": [{**base, "note": "at or above 2.4.71"}]}
        return {"status": "vulnerable",
                "details": [{**base, "note": "upgrade apache24 to 2.4.71 or later"}]}

    # Debian / Ubuntu: distro packages backport, so judge by the published fixed package.
    table = DEBIAN_FIXED if distro == "debian" else UBUNTU_FIXED
    fixed = table.get(rel)
    if fixed:
        vulnerable = version_less_than(run, family, inst, fixed)
        return {"status": "vulnerable" if vulnerable else "ok",
                "details": [{**base, "fixed_version": fixed}]}

    return {"status": "review",
            "details": [{**base, "note": f"upstream version is in the affected range "
                                         f"but no fixed {distro or 'distro'} {rel} package "
                                         f"is confirmed yet; check {advisory} and "
                                         f"re-scan after patching"}]}


def mitigation_check(run, osinfo):
    """Exposure posture: the bug is in mod_http2, so no module / no h2 = no exposure."""
    family = osinfo["family"]
    if family not in ("ubuntu", "debian", "freebsd"):
        return {"status": "not_applicable", "details": [{"note": "unsupported OS family"}]}

    pkg, inst = _find_apache(run, osinfo)
    if inst is None:
        return {"status": "not_applicable",
                "details": [{"note": "Apache HTTP Server package not installed"}]}

    if family == "freebsd":
        conf = "/usr/local/etc/apache24"
        _, mods, _ = run(f"grep -rhE '^[[:space:]]*LoadModule[[:space:]]+http2_module' {conf}")
        _, protos, _ = run(f"grep -rhiE '^[[:space:]]*Protocols[[:space:]]' {conf}")
        loaded = bool(mods.strip())
    else:
        conf = "/etc/apache2"
        code, _, _ = run(f"test -e {conf}/mods-enabled/http2.load")
        _, mods, _ = run(f"grep -rhE '^[[:space:]]*LoadModule[[:space:]]+http2_module' "
                         f"{conf} --include=*.conf --include=*.load")
        _, protos, _ = run(f"grep -rhiE '^[[:space:]]*Protocols[[:space:]]' {conf}")
        loaded = code == 0 or bool(mods.strip())

    h2_lines = [l.strip() for l in protos.splitlines()
                if re.search(r"\bh2c?\b", l, re.I)]
    info = {"mod_http2_loaded": loaded, "protocols_h2": h2_lines or "none found"}

    if not loaded:
        return {"status": "mitigated",
                "details": [{**info, "note": "mod_http2 not loaded - vulnerable code "
                                             "not reachable; not a substitute for the patch"}]}
    if h2_lines:
        return {"status": "not_mitigated",
                "details": [{**info, "note": "mod_http2 loaded and HTTP/2 enabled via "
                                             "Protocols; disable until patched"}]}
    return {"status": "review",
            "details": [{**info, "note": "mod_http2 is loaded but no Protocols h2 line "
                                         "was found in the config; confirm HTTP/2 is "
                                         "really off (per-vhost settings, other include "
                                         "paths)"}]}


REMEDIATION = """# The fix

Upgrade Apache HTTP Server to **2.4.71 or later** (the upstream fix), or to your
distribution's fixed package. The CNA lists 2.4.55 through 2.4.70 as affected; the
GitHub mod_h2 module is affected from 2.0.8 through 2.0.42.

Debian / Ubuntu:

```
sudo apt update
sudo apt install --only-upgrade apache2
apache2 -v          # confirm the version
sudo systemctl restart apache2
```

FreeBSD:

```
doas pkg upgrade apache24
doas service apache24 restart
```

Fixed packages published so far:

- Debian 13 (trixie): apache2 2.4.71-1~deb13u1 (DSA-6620-1)
- Debian 12 (bookworm), Debian 11, Ubuntu: no confirmed fixed package at the time
  this definition was written - check
  https://security-tracker.debian.org/tracker/CVE-2026-119618 and
  https://ubuntu.com/security/CVE-2026-119618, then update the tables in this file.
- Upstream advisory: https://httpd.apache.org/security/vulnerabilities_24.html

# Interim mitigation (reduces exposure, not a fix)

The bug is in `mod_http2`. If you don't need HTTP/2, remove it from the attack surface:

```
sudo a2dismod http2 && sudo systemctl restart apache2      # Debian / Ubuntu
```

and/or remove `h2` / `h2c` from every `Protocols` line (e.g. `Protocols http/1.1`).
On FreeBSD, comment out `LoadModule http2_module ...` in
`/usr/local/etc/apache24/` and restart. Verify with `apache2ctl -M | grep http2`
(should print nothing). Re-enable HTTP/2 only after patching.

# Not affected

Hosts without Apache HTTP Server, and hosts running a version below 2.4.55.
Nginx and other web servers are not affected by this CVE.
"""
