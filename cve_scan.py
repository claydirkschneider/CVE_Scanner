#!/usr/bin/env python3
"""
Fleet CVE audit over SSH (password auth).

Sweeps a subnet, checks the target port is open, logs into each reachable host,
detects OS + version, and runs a CVE check loaded from a definition file.
Records every IP in the range, with its state and findings, to JSON and CSV.

The CVE logic lives in cves/<CVE>.py (see cvelib.py for the contract); this
scanner is CVE-agnostic. Pick one with --cve. Designed for auditing your OWN
servers (mixed FreeBSD + Ubuntu/Debian).

Dependency: paramiko  ->  pip install paramiko   (FreeBSD: pkg install py311-paramiko)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import getpass
import ipaddress
import json
import logging
import os
import socket
import sys
from datetime import datetime, timezone

import cvelib

try:
    import paramiko
except ImportError:
    sys.exit("paramiko is required. Install with: pip install paramiko")

# Paramiko logs handshake failures (e.g. "Error reading SSH protocol banner") as
# tracebacks from its transport thread. We already surface those hosts as
# 'ssh_error', so silence paramiko's own logging to keep output readable.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

DEFAULT_CVE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cves")


def ssh_exec(client, cmd: str, timeout: int = 15):
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


def scan_host(host, port, username, password, timeout, cve_mod, mitigation=False) -> dict:
    """Always returns a record. 'state' says what happened to this IP."""
    result = {"host": host, "scanned_at": datetime.now(timezone.utc).isoformat(),
              "state": None}

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
        result["state"] = "auth_failed"
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
        result["cve"] = cve_mod.CVE_ID
        try:
            result["cve_check"] = cve_mod.cve_check(run, osinfo)
        except Exception as e:  # a bad definition shouldn't kill the host record
            result["cve_check"] = {"status": "error", "details": [str(e)]}
        if mitigation and hasattr(cve_mod, "mitigation_check"):
            try:
                result["mitigation"] = cve_mod.mitigation_check(run, osinfo)
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
        description="Audit a subnet over SSH for a CVE loaded from cves/ "
                    "(your own servers).")
    ap.add_argument("--cve", required=True,
                    help="CVE ID to check, e.g. CVE-2026-109518 "
                         "(loads cves/CVE_2026_109518.py).")
    ap.add_argument("--cve-dir", default=DEFAULT_CVE_DIR,
                    help="Directory of CVE definition files (default: cves/ "
                         "next to this script).")
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
                    help="Also run the definition's mitigation_check() per host "
                         "(exposure/workaround posture, independent of patch status).")
    args = ap.parse_args()

    try:
        cve_mod = cvelib.load_cve(args.cve, args.cve_dir)
    except (FileNotFoundError, AttributeError) as e:
        sys.exit(f"[!] {e}")
    cve_id = cve_mod.CVE_ID

    if args.mitigation_check and not hasattr(cve_mod, "mitigation_check"):
        print(f"[!] {cve_id} has no mitigation_check(); --mitigation-check ignored.",
              file=sys.stderr)

    password = os.environ.get(args.password_env)
    if not password:
        password = getpass.getpass(f"SSH password for {args.username}: ")

    targets = expand_targets(args.subnet)
    print(f"[*] {len(targets)} target(s). Checking port {args.port}, then auditing "
          f"for {cve_id} as {args.username} ({args.workers} workers)...",
          file=sys.stderr)

    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {
            ex.submit(scan_host, h, args.port, args.username, password,
                      args.timeout, cve_mod, args.mitigation_check): h
            for h in targets
        }
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            results.append(res)
            state = res.get("state", "?")
            if state == "logged_in":
                status = res.get("cve_check", {}).get("status", "?")
                extra = ""
                if args.mitigation_check and "mitigation" in res:
                    extra = f" MIT:{res['mitigation'].get('status', '?')}"
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

    json_path = f"{args.output}.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)

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

    # Remediation sidecar for the report (comes from the CVE definition).
    rem_path = None
    remediation = getattr(cve_mod, "REMEDIATION", "")
    if remediation.strip():
        rem_path = f"{args.output}.remediation.md"
        with open(rem_path, "w") as f:
            f.write(remediation)

    counts: dict[str, int] = {}
    for r in results:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    vuln = sum(1 for r in results
               if r.get("cve_check", {}).get("status") == "vulnerable")

    print(f"\n[*] {cve_id}: {len(results)} IP(s) scanned:", file=sys.stderr)
    for state in sorted(counts):
        print(f"      {state:<12} {counts[state]}", file=sys.stderr)
    print(f"[*] {vuln} host(s) flagged VULNERABLE.", file=sys.stderr)
    msg = f"[*] Wrote {json_path} and {csv_path} (full range, every IP)."
    if rem_path:
        msg += f" Remediation: {rem_path}"
    print(msg, file=sys.stderr)


if __name__ == "__main__":
    main()