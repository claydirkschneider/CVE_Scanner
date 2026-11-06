"""CVE-2026-98432 — Linux kernel IPv4 TCP handshake use-after-free (CVSS 9.8).

A remote, unauthenticated use-after-free reachable via the IPv4 TCP handshake.
Linux-kernel only; FreeBSD and other non-Linux systems are not affected. Verdict
is driven by the running kernel's package version. The MPTCP-listener path is the
demonstrated remote-root route; the lower-impact DoS/mem-corruption path does not
need MPTCP.
"""

from cvelib import version_less_than

CVE_ID = "CVE-2026-98432"
ADVISORY_URL = "https://ubuntu.com/security/CVE-2026-98432"

# Ubuntu/Debian: compare the running kernel's linux-image package. Keyed by
# VERSION_ID; each maps a kernel-flavor substring (as in `uname -r`) to the first
# FIXED dpkg version. VERIFY / UPDATE from Canonical; fixes were still rolling out
# in early Nov 2026, so an unlisted release/flavor reports "review", not "ok".
UBUNTU_FIXED = {
    # "24.04": {"generic": "6.8.0-00.00", "aws": "6.8.0-00.00", "azure": "6.8.0-00.00"},
    # "22.04": {"generic": "5.15.0-000.000"},
    # "20.04": {"generic": "5.4.0-000.000"},
}

# FreeBSD base system via `freebsd-version`. EMPTY because FreeBSD is NOT affected
# by this CVE; shape shown for the next CVE that does hit the FreeBSD base.
FREEBSD_FIXED = {
    # "13.2-RELEASE": "13.2-RELEASE-p9",
}


def _check_ubuntu(run, osinfo):
    rel = osinfo.get("version", "")
    _, krel, _ = run("uname -r")  # e.g. 5.15.0-125-generic
    code, pkgver, _ = run(f"dpkg-query -W -f='${{Version}}' linux-image-{krel} 2>/dev/null")
    pkgver = pkgver if (code == 0 and pkgver) else None

    _, mptcp, _ = run("cat /proc/sys/net/mptcp/enabled 2>/dev/null")
    base = {"kernel": krel, "installed_pkg_version": pkgver,
            "mptcp_listener_possible": mptcp.strip() == "1", "advisory": ADVISORY_URL}

    table = UBUNTU_FIXED.get(rel)
    if not table or not pkgver:
        return {"status": "review",
                "details": [{**base, "note": "no confirmed fixed version for this "
                                             "release/flavor — check the tracker"}]}
    fixed_ver = next((fv for flavor, fv in table.items() if flavor in krel), None)
    if fixed_ver is None:
        return {"status": "review",
                "details": [{**base, "note": "kernel flavor not in UBUNTU_FIXED"}]}

    vulnerable = version_less_than(run, osinfo["family"], pkgver, fixed_ver)
    return {"status": "vulnerable" if vulnerable else "ok",
            "details": [{**base, "fixed_version": fixed_ver,
                         "impact": "RCE if an MPTCP listener is present; "
                                   "otherwise remote DoS / kernel memory corruption"}]}


def _check_freebsd(run, osinfo):
    if not FREEBSD_FIXED:
        return {"status": "not_applicable",
                "details": [{"note": "FreeBSD not affected by this CVE "
                                     "(Linux-kernel IPv4 TCP bug)"}]}
    _, fbver, _ = run("freebsd-version 2>/dev/null || uname -r")
    relkey = fbver.split("-p")[0]
    base = {"freebsd_version": fbver}
    fixed = FREEBSD_FIXED.get(relkey)
    if not fixed:
        return {"status": "review",
                "details": [{**base, "note": "release not in FREEBSD_FIXED; verify"}]}
    _, out, _ = run(f"pkg version -t '{fbver}' '{fixed}'")
    vulnerable = out.strip() == "<"
    return {"status": "vulnerable" if vulnerable else "ok",
            "details": [{**base, "fixed_version": fixed}]}


def cve_check(run, osinfo):
    family = osinfo["family"]
    if family in ("ubuntu", "debian", "linux"):
        return _check_ubuntu(run, osinfo)
    if family == "freebsd":
        return _check_freebsd(run, osinfo)
    return {"status": "not_applicable",
            "details": [{"note": f"no table for OS family '{family}'"}]}


def mitigation_check(run, osinfo):
    # Workaround is to disable MPTCP where it isn't needed. Read the knob from
    # /proc (PATH-proof; sysctl lives in /usr/sbin, not always on a non-login PATH).
    family = osinfo["family"]
    if family not in ("ubuntu", "debian", "linux"):
        return {"status": "not_applicable",
                "details": [{"note": "no mitigation check defined for this OS"}]}

    _, mptcp, _ = run("cat /proc/sys/net/mptcp/enabled 2>/dev/null")
    _, migrate, _ = run("cat /proc/sys/net/ipv4/tcp_migrate_req 2>/dev/null")
    _, nlisten, _ = run("PATH=/usr/sbin:/sbin:$PATH ss -H -lMn 2>/dev/null | wc -l")
    try:
        listeners = int(nlisten.strip())
    except (ValueError, AttributeError):
        listeners = None

    m = mptcp.strip()
    info = {"net.mptcp.enabled": m or "absent",
            "net.ipv4.tcp_migrate_req": migrate.strip() or "absent",
            "mptcp_listeners": listeners}

    if m == "0":
        return {"status": "mitigated",
                "details": [{**info, "note": "MPTCP disabled (workaround applied; "
                                             "not a substitute for a patched kernel)"}]}
    if m == "1":
        note = ("MPTCP enabled with active listener(s)" if listeners
                else "MPTCP enabled (new sockets allowed)")
        return {"status": "not_mitigated", "details": [{**info, "note": note}]}
    return {"status": "not_applicable",
            "details": [{**info, "note": "kernel has no MPTCP support "
                                         "(net.mptcp.enabled absent)"}]}


REMEDIATION = """# The fix

The only complete fix is a **patched Linux kernel**. Install your distribution's
fixed kernel package and reboot, then confirm the running kernel matches the
fixed version in the vendor advisory for each release and flavor.

- Ubuntu: https://ubuntu.com/security/CVE-2026-98432
- Debian: a fixed kernel has shipped - `apt upgrade` and reboot
- RHEL family: https://access.redhat.com/security/cve/cve-2026-98432

Debian / Ubuntu steps:

```
sudo apt update && sudo apt upgrade
sudo reboot
uname -r        # confirm the running kernel is the fixed version
```

# Interim mitigation (reduces exposure, not a fix)

While a fixed kernel is pending, disable MPTCP where nothing needs it. This
removes the listener the demonstrated remote-root chain depends on, but does not
remove the bug, and MPTCP is not required for the lower-impact DoS path.

```
echo 'net.mptcp.enabled = 0'        | sudo tee  /etc/sysctl.d/99-cve-2026-98432.conf
echo 'net.ipv4.tcp_migrate_req = 0' | sudo tee -a /etc/sysctl.d/99-cve-2026-98432.conf
sudo sysctl --system
```

Restart services that already hold an MPTCP listener. The setting is per network
namespace, so containers need it set in their own namespace.

# Not affected

FreeBSD is not affected - this is a Linux-kernel IPv4 TCP bug. No action required.
"""