#!/usr/bin/env python3
"""
Fleet CVE audit over SSH (password auth).

Sweeps a subnet, checks the target port is open, logs into each reachable host,
detects OS + version, and runs a pluggable per-CVE check.
Records every host it logged into, with its info, to JSON and CSV.

Designed for auditing your OWN servers (mixed FreeBSD + Ubuntu).

Dependency: paramiko  ->  pip install paramiko
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import getpass
import ipaddress
import json
import os
import socket
import sys
from datetime import datetime, timezone

import logging

try:
    import paramiko
except ImportError:
    sys.exit("paramiko is required. Install with: pip install paramiko")

# Paramiko logs handshake failures (e.g. "Error reading SSH protocol banner")
# as tracebacks from its transport thread. We already surface those hosts as
# 'ssh_error', so silence paramiko's own logging to keep output readable.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)


CVE_ID = "CVE-2026-98432"

# Declarative definitions used by the DEFAULT check below. Simple cases only:
# "this package below this version is vulnerable". For anything more involved,
# replace the cve_check() function further down.
VULN_DEFS = {
    "ubuntu": [
        # {"package": "openssl", "fixed_version": "3.0.2-0ubuntu1.18"},
    ],
    "freebsd": [
        # {"package": "openssl", "fixed_version": "3.0.12,1"},
        # Base-system CVE: use package "__base__", compare against e.g. "13.2-RELEASE-p9".
        # {"package": "__base__", "fixed_version": "13.2-RELEASE-p9"},
    ],
}


# --------------------------------------------------------------------------
# Remote helpers available to any cve_check you write.
#   run(cmd, timeout=15) -> (exit_code, stdout, stderr)
# --------------------------------------------------------------------------
def installed_version(run, family: str, package: str) -> str | None:
    """Installed version string of a package, or None if absent."""
    if package == "__base__":
        _, ver, _ = run("freebsd-version 2>/dev/null || uname -r")
        return ver or None
    if family in ("ubuntu", "debian"):
        code, out, _ = run(f"dpkg-query -W -f='${{Version}}' {package} 2>/dev/null")
        return out if code == 0 and out else None
    if family == "freebsd":
        code, out, _ = run(f"pkg query '%v' {package} 2>/dev/null")
        return out if code == 0 and out else None
    return None


def version_less_than(run, family: str, installed: str, fixed: str) -> bool:
    """Compare versions using the host's NATIVE tooling (correct for odd strings)."""
    if family in ("ubuntu", "debian"):
        code, _, _ = run(f"dpkg --compare-versions '{installed}' lt '{fixed}'")
        return code == 0  # exit 0 == comparison true
    if family == "freebsd":
        _, out, _ = run(f"pkg version -t '{installed}' '{fixed}'")
        return out.strip() == "<"
    return False


# ##########################################################################
# ####  CVE CHECK  —  PASTE / REPLACE THIS FUNCTION PER CVE  ###############
# ##########################################################################
#
# Contract:
#   args:
#     run(cmd, timeout=15) -> (exit_code, stdout, stderr)   # runs on the host
#     osinfo -> {"family": "ubuntu"|"freebsd"|..., "os": str, "version": str}
#   return a dict:
#     {"status": "vulnerable" | "ok" | "not_applicable" | "no_definition" | "error",
#      "details": [...]}            # details is anything JSON-serializable
#
# Helpers you can call: installed_version(run, family, pkg),
#                       version_less_than(run, family, installed, fixed)
#
# The default below just applies VULN_DEFS. Replace the whole function body
# (or the whole function) with a generated check for a specific CVE.
# --------------------------------------------------------------------------
ADVISORY_URL = "https://ubuntu.com/security/CVE-2026-98432"

# --- Fixed-version tables, one per OS. The check consults whichever matches --
# the host. An EMPTY table means "this OS has no definition for this CVE" and
# the host is reported not_applicable. A host whose release/flavor isn't listed
# in a non-empty table is reported "review" (never a false "ok").

# Ubuntu/Debian: this CVE is a KERNEL bug, so we compare the running kernel's
# linux-image package. Keyed by VERSION_ID (from /etc/os-release); each maps a
# kernel-flavor substring (as in `uname -r`) to the first FIXED dpkg version.
# VERIFY / UPDATE from Canonical; fixes were still rolling out in early Nov 2026.
UBUNTU_FIXED = {
    # "24.04": {"generic": "6.8.0-00.00", "aws": "6.8.0-00.00", "azure": "6.8.0-00.00"},
    # "22.04": {"generic": "5.15.0-000.000"},
    # "20.04": {"generic": "5.4.0-000.000"},
}

# FreeBSD: compares the base system via `freebsd-version` (e.g. 13.2-RELEASE-p5).
# Keyed by release prefix (before "-p") -> first FIXED patch level.
# EMPTY for CVE-2026-98432 because FreeBSD is NOT affected (Linux-kernel bug).
# Shape shown for the next CVE that does hit the FreeBSD base system:
FREEBSD_FIXED = {
    # "13.2-RELEASE": "13.2-RELEASE-p9",
    # "14.0-RELEASE": "14.0-RELEASE-p5",
}


def _check_ubuntu(run, osinfo: dict) -> dict:
    rel = osinfo.get("version", "")
    _, krel, _ = run("uname -r")  # e.g. 5.15.0-125-generic
    code, pkgver, _ = run(f"dpkg-query -W -f='${{Version}}' linux-image-{krel} 2>/dev/null")
    pkgver = pkgver if (code == 0 and pkgver) else None

    # MPTCP exposure distinguishes the RCE path from DoS/memory-corruption.
    _, mptcp, _ = run("sysctl -n net.mptcp.enabled 2>/dev/null")
    base = {"kernel": krel, "installed_pkg_version": pkgver,
            "mptcp_listener_possible": mptcp.strip() == "1",
            "advisory": ADVISORY_URL}

    table = UBUNTU_FIXED.get(rel)
    if not table or not pkgver:
        return {"status": "review",
                "details": [{**base, "note": "no confirmed fixed version for this "
                                             "release/flavor — check the tracker"}]}
    fixed_ver = next((fv for flavor, fv in table.items() if flavor in krel), None)
    if fixed_ver is None:
        return {"status": "review",
                "details": [{**base, "note": "kernel flavor not in UBUNTU_FIXED"}]}

    code, _, _ = run(f"dpkg --compare-versions '{pkgver}' lt '{fixed_ver}'")
    vulnerable = code == 0  # installed < fixed
    return {"status": "vulnerable" if vulnerable else "ok",
            "details": [{**base, "fixed_version": fixed_ver,
                         "impact": "RCE if an MPTCP listener is present; "
                                   "otherwise remote DoS / kernel memory corruption"}]}


def _check_freebsd(run, osinfo: dict) -> dict:
    if not FREEBSD_FIXED:
        return {"status": "not_applicable",
                "details": [{"note": "FreeBSD not affected by this CVE "
                                     "(Linux-kernel IPv4 TCP bug)"}]}
    _, fbver, _ = run("freebsd-version 2>/dev/null || uname -r")  # 13.2-RELEASE-p5
    relkey = fbver.split("-p")[0]  # 13.2-RELEASE
    base = {"freebsd_version": fbver}
    fixed = FREEBSD_FIXED.get(relkey)
    if not fixed:
        return {"status": "review",
                "details": [{**base, "note": "release not in FREEBSD_FIXED; verify"}]}
    _, out, _ = run(f"pkg version -t '{fbver}' '{fixed}'")  # prints <, = or >
    vulnerable = out.strip() == "<"
    return {"status": "vulnerable" if vulnerable else "ok",
            "details": [{**base, "fixed_version": fixed}]}


def cve_check(run, osinfo: dict) -> dict:
    """CVE-2026-98432 — Linux kernel IPv4 TCP handshake use-after-free (CVSS 9.8).

    Generic dispatch by OS family: each OS has its own fixed-version table above,
    and the script just checks the host against the matching one.
    """
    family = osinfo["family"]
    if family in ("ubuntu", "debian", "linux"):
        return _check_ubuntu(run, osinfo)
    if family == "freebsd":
        return _check_freebsd(run, osinfo)
    return {"status": "not_applicable",
            "details": [{"note": f"no table for OS family '{family}'"}]}


# ---- Example of a pasted custom check (left commented for reference) ------
# def cve_check(run, osinfo):
#     """Example: flag if a config-based mitigation is NOT present."""
#     family = osinfo["family"]
#     if family != "ubuntu":
#         return {"status": "not_applicable", "details": []}
#     inst = installed_version(run, family, "nginx")
#     if inst is None:
#         return {"status": "not_applicable", "details": ["nginx not installed"]}
#     vuln = version_less_than(run, family, inst, "1.25.4-0ubuntu1")
#     # also require that a workaround flag is absent to count as vulnerable:
#     code, out, _ = run("grep -q 'ssl_reject_handshake' /etc/nginx/nginx.conf; echo $?")
#     mitigated = out.strip() == "0"
#     status = "vulnerable" if (vuln and not mitigated) else "ok"
#     return {"status": status,
#             "details": [{"nginx": inst, "mitigated": mitigated}]}
# ##########################################################################


# ##########################################################################
# ####  MITIGATION CHECK  —  OPTIONAL, PASTE / REPLACE PER CVE  ############
# ##########################################################################
#
# Runs only when --mitigation-check is passed. Same contract as cve_check:
#   mitigation_check(run, osinfo) -> {"status": <str>, "details": [...]}
# Reports the MITIGATION / EXPOSURE posture of a host, independent of whether
# the kernel/package is patched. Useful while a vendor fix is pending and you're
# relying on a workaround (a sysctl, an nftables rule, a disabled feature).
#
# Suggested statuses:
#   "mitigated"      workaround is in place
#   "not_mitigated"  workaround is absent / exposed
#   "not_applicable" no mitigation concept for this OS/CVE
#   "review" / "error"
#
# Replace the body per CVE. The shipped version reports MPTCP exposure, the
# workaround for CVE-2026-98432 (not a fix — see the advisory).
# --------------------------------------------------------------------------
def mitigation_check(run, osinfo: dict) -> dict:
    family = osinfo["family"]
    if family not in ("ubuntu", "debian", "linux"):
        return {"status": "not_applicable",
                "details": [{"note": "no mitigation check defined for this OS"}]}

    # Read the kernel knobs straight from /proc. `sysctl`/`ss` live in /usr/sbin,
    # which isn't always on a non-login SSH PATH (Debian especially), so calling
    # them by name reads empty on some hosts. /proc is PATH-proof and the files
    # are world-readable when the feature exists.
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
    # Knob absent -> this kernel has no MPTCP support, so the MPTCP RCE path
    # doesn't apply (the IPv4 DoS/mem-corruption path still depends on the patch).
    return {"status": "not_applicable",
            "details": [{**info, "note": "kernel has no MPTCP support "
                                         "(net.mptcp.enabled absent)"}]}


def ssh_exec(client: paramiko.SSHClient, cmd: str, timeout: int = 15):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="replace").strip()
    err = stderr.read().decode(errors="replace").strip()
    code = stdout.channel.recv_exit_status()
    return code, out, err


def detect_os(run) -> dict:
    _, kernel, _ = run("uname -s")
    if kernel == "FreeBSD":
        _, ver, _ = run("freebsd-version 2>/dev/null || uname -r")
        return {"family": "freebsd", "os": "FreeBSD", "version": ver}

    _, osr, _ = run("cat /etc/os-release 2>/dev/null")
    fields = {}
    for line in osr.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            fields[k] = v.strip().strip('"')
    distro_id = fields.get("ID", "").lower()
    pretty = fields.get("PRETTY_NAME") or fields.get("NAME", "Linux")
    version = fields.get("VERSION_ID", "")
    family = "ubuntu" if distro_id in ("ubuntu", "debian") else distro_id or "linux"
    return {"family": family, "os": pretty, "version": version}


def port_open(host: str, port: int, timeout: float) -> bool:
    """Fast raw-socket check before attempting SSH."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_host(host, port, username, password, timeout, mitigation=False) -> dict:
    """Always returns a record. 'state' says what happened to this IP."""
    result = {"host": host, "scanned_at": datetime.now(timezone.utc).isoformat(),
              "state": None}

    # 1) cheap port check first
    if not port_open(host, port, timeout):
        result["state"] = "port_closed"
        return result

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, port=port, username=username, password=password,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            allow_agent=False, look_for_keys=False,
        )
    except paramiko.AuthenticationException:
        result["state"] = "auth_failed"  # reachable, SSH up, wrong creds
        return result
    except (socket.timeout, socket.error, paramiko.SSHException, OSError) as e:
        result["state"] = "ssh_error"
        result["error"] = str(e)
        return result

    def run(cmd, timeout_=15):
        return ssh_exec(client, cmd, timeout_)

    try:
        osinfo = detect_os(run)
        result.update(osinfo)
        result["cve"] = CVE_ID
        try:
            result["cve_check"] = cve_check(run, osinfo)
        except Exception as e:  # a bad pasted check shouldn't kill the host record
            result["cve_check"] = {"status": "error", "details": [str(e)]}
        if mitigation:
            try:
                result["mitigation"] = mitigation_check(run, osinfo)
            except Exception as e:
                result["mitigation"] = {"status": "error", "details": [str(e)]}
        result["state"] = "logged_in"
        return result
    except Exception as e:  # noqa: BLE001
        result["state"] = "info_error"
        result["error"] = f"info_gathering_failed: {e}"
        return result
    finally:
        client.close()


def expand_targets(subnets: list[str]) -> list[str]:
    hosts: list[str] = []
    for spec in subnets:
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                net = ipaddress.ip_network(part, strict=False)
                hosts.extend(str(h) for h in net.hosts())
            except ValueError:
                hosts.append(part)
    return hosts


def main() -> None:
    ap = argparse.ArgumentParser(
        description=f"Audit a subnet over SSH for {CVE_ID} (your own servers).")
    ap.add_argument("--subnet", required=True, action="append",
                    help="CIDR, single IP, or comma list. Repeatable. e.g. 10.0.0.0/24")
    ap.add_argument("--username", "-u", required=True)
    ap.add_argument("--password-env", default="SSH_PASSWORD",
                    help="Env var holding the password (default: SSH_PASSWORD). "
                         "If unset, you'll be prompted.")
    ap.add_argument("--port", "-p", type=int, default=22)
    ap.add_argument("--workers", "-w", type=int, default=20)
    ap.add_argument("--timeout", "-t", type=int, default=8,
                    help="Per-connection/port timeout, seconds (default 8).")
    ap.add_argument("--output", "-o", default="cve_scan_results")
    ap.add_argument("--mitigation-check", action="store_true",
                    help="Also run the mitigation_check() hook per host "
                         "(exposure/workaround posture, independent of patch status).")
    args = ap.parse_args()

    password = os.environ.get(args.password_env)
    if not password:
        password = getpass.getpass(f"SSH password for {args.username}: ")

    targets = expand_targets(args.subnet)
    print(f"[*] {len(targets)} target(s). Checking port {args.port}, then auditing "
          f"for {CVE_ID} as {args.username} ({args.workers} workers)...",
          file=sys.stderr)

    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {
            ex.submit(scan_host, h, args.port, args.username, password,
                      args.timeout, args.mitigation_check): h
            for h in targets
        }
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            results.append(res)
            state = res.get("state", "?")
            # Quiet: only show hosts we logged into and genuine errors.
            # 'port_closed' is the noisy common case -> kept in files, not on screen.
            if state == "logged_in":
                status = res.get("cve_check", {}).get("status", "?")
                extra = ""
                if args.mitigation_check:
                    extra = f" MIT:{res.get('mitigation', {}).get('status', '?')}"
                print(f"[+] {res['host']:<16} {state:<12} {res.get('os','?'):<26} "
                      f"{res.get('version',''):<14} CVE:{status}{extra}", file=sys.stderr)
            elif state in ("ssh_error", "info_error", "auth_failed"):
                print(f"[-] {res['host']:<16} {state}", file=sys.stderr)
            # port_closed: silent on screen

    def sort_key(r):
        h = r["host"]
        try:
            return (0, tuple(int(x) for x in h.split(".")))
        except ValueError:
            return (1, (h,))
    results.sort(key=sort_key)

    # JSON: the entire range, every IP with its state
    json_path = f"{args.output}.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)

    # CSV: every IP, one row, with a state column
    csv_path = f"{args.output}.csv"
    with open(csv_path, "w", newline="") as f:
        wr = csv.writer(f)
        header = ["host", "state", "os", "version", "family",
                  "cve", "cve_status", "details"]
        if args.mitigation_check:
            header += ["mitigation_status", "mitigation_details"]
        wr.writerow(header)
        for r in results:
            cc = r.get("cve_check", {})
            row = [
                r["host"], r.get("state", ""), r.get("os", ""), r.get("version", ""),
                r.get("family", ""), r.get("cve", "") if r.get("state") == "logged_in" else "",
                cc.get("status", ""), json.dumps(cc.get("details", [])) if cc else "",
            ]
            if args.mitigation_check:
                mit = r.get("mitigation", {})
                row += [mit.get("status", ""),
                        json.dumps(mit.get("details", [])) if mit else ""]
            wr.writerow(row)

    # Summary counts by state
    counts: dict[str, int] = {}
    for r in results:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    vuln = sum(1 for r in results
               if r.get("cve_check", {}).get("status") == "vulnerable")

    print(f"\n[*] {len(results)} IP(s) scanned:", file=sys.stderr)
    for state in sorted(counts):
        print(f"      {state:<12} {counts[state]}", file=sys.stderr)
    print(f"[*] {vuln} host(s) flagged VULNERABLE.", file=sys.stderr)
    print(f"[*] Wrote {json_path} and {csv_path} (full range, every IP).",
          file=sys.stderr)


if __name__ == "__main__":
    main()