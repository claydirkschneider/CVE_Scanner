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
import re
import shlex
import socket
import sys
import time
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


# Vendor-CLI commands (network gear) must go to the device as-is; everything else
# is POSIX shell and is wrapped so a csh/tcsh login shell (pfSense, some FreeBSD
# accounts) can't mangle `2>/dev/null`, `VAR=x cmd`, etc.
CLI_PREFIXES = ("show ", "get system status")


def sh_wrap(cmd: str) -> str:
    return cmd if cmd.startswith(CLI_PREFIXES) else "/bin/sh -c " + shlex.quote(cmd)


def ssh_exec(client, cmd: str, timeout: int = 15):
    cmd = sh_wrap(cmd)
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="replace").strip()
    err = stderr.read().decode(errors="replace").strip()
    code = stdout.channel.recv_exit_status()
    return code, out, err


# --- device fingerprinting -------------------------------------------------
# Network gear (Arista EOS, Cisco, Junos, FortiOS) usually drops SSH logins into a
# vendor CLI where `uname` fails, so we probe vendor commands when the host does
# not answer like a Unix box.

def _role_from_model(vendor: str, model: str) -> str:
    m = (model or "").lower()
    if vendor == "Arista":
        return "router" if m.startswith(("dcs-7500", "dcs-7800")) else "switch"
    if vendor == "Fortinet":
        return "firewall"
    if vendor == "Juniper":
        if m.startswith(("srx", "vsrx")):
            return "firewall"
        if m.startswith(("mx", "ptx", "acx")):
            return "router"
        if m.startswith(("ex", "qfx")):
            return "switch"
    if vendor == "Cisco":
        if "asa" in m or "firepower" in m or "ftd" in m:
            return "firewall"
        if m.startswith(("n", "ws-", "c9", "c3", "c2")) or "nexus" in m or "catalyst" in m:
            return "switch"
        if m.startswith(("isr", "asr", "csr", "c8")):
            return "router"
    return "unknown"


def _network_info(vendor, os_name, version, model) -> dict:
    return {"family": "network", "os": os_name, "version": version,
            "vendor": vendor, "model": model,
            "role": _role_from_model(vendor, model)}


def detect_network_device(run) -> dict | None:
    """Return osinfo for a recognised network appliance, else None."""
    _, out, _ = run("show version")
    if re.search(r"\bArista\b", out):
        model = (re.search(r"Arista\s+(\S+)", out) or [None, ""])[1]
        ver = (re.search(r"Software image version:\s*(\S+)", out) or [None, ""])[1]
        return _network_info("Arista", "Arista EOS", ver, model)
    if "Cisco" in out:
        ver = (re.search(r"(?:Version|system:\s+version)\s+([\w.()\-]+)", out) or [None, ""])[1]
        if "NX-OS" in out or "Nexus" in out:
            m = re.search(r"cisco\s+(Nexus\S*\s*\S*)", out, re.I)
            return _network_info("Cisco", "Cisco NX-OS", ver, m.group(1) if m else "Nexus")
        if "Adaptive Security Appliance" in out:
            return _network_info("Cisco", "Cisco ASA", ver, "ASA")
        m = re.search(r"[Cc]isco\s+(\S+)\s+\(.*?\)\s+processor", out)
        return _network_info("Cisco", "Cisco IOS", ver, m.group(1) if m else "")
    if re.search(r"Junos:", out):
        ver = (re.search(r"Junos:\s*(\S+)", out) or [None, ""])[1]
        model = (re.search(r"Model:\s*(\S+)", out) or [None, ""])[1]
        return _network_info("Juniper", "Junos", ver, model)
    _, out, _ = run("get system status")
    if "Forti" in out:
        m = re.search(r"Version:\s*(Forti\S+)\s+v?([\w.]+)", out)
        return _network_info("Fortinet", "FortiOS", m.group(2) if m else "",
                             m.group(1) if m else "FortiGate")
    return None


def detect_freebsd_firewall(run, base_ver: str) -> dict | None:
    """FreeBSD-based firewall distros: pfSense (CE/Plus) and OPNsense.

    Uses several independent signals (platform file, pfSense-only paths, pfSense
    packages, kernel ident) because no single one is guaranteed on every release.
    No shell redirects: run() already captures stderr separately, and redirect
    syntax breaks under csh/tcsh login shells."""
    _, plat, _ = run("cat /etc/platform")
    _, paths, _ = run("ls /etc/inc/globals.inc /usr/local/sbin/pfSense-upgrade "
                      "/usr/local/share/pfSense /usr/local/pfSense /cf/conf/config.xml")
    _, pkgs, _ = run("pkg info -x '^pfSense'")
    _, uname_a, _ = run("uname -a")
    is_pfsense = (
        "pfsense" in plat.lower()
        or "/etc/inc/globals.inc" in paths
        or "pfSense-upgrade" in paths
        or any(l.lower().startswith("pfsense") for l in pkgs.splitlines())
        or re.search(r"RELENG_|plus-RELENG|pfSense", uname_a) is not None
    )
    if is_pfsense:
        _, ver, _ = run("cat /etc/version")
        ver = ver.strip()
        _, model, _ = run("kenv smbios.system.product")
        plus = bool(re.match(r"\d{2}\.\d{2}", ver))   # Plus: 24.03; CE: 2.7.2
        info = _network_info("Netgate", "pfSense Plus" if plus else "pfSense CE",
                             ver, model.strip())
        info["role"] = "firewall"
        info["base_os"] = f"FreeBSD {base_ver}"
        return info
    _, ons, _ = run("opnsense-version")
    if ons.strip().lower().startswith("opnsense"):
        m = re.match(r"OPNsense\s+(\S+)", ons.strip(), re.I)
        info = _network_info("OPNsense", "OPNsense", m.group(1) if m else "", "")
        info["role"] = "firewall"
        info["base_os"] = f"FreeBSD {base_ver}"
        return info
    return None


def detect_os(run) -> dict:
    code, kernel, _ = run("uname -s")
    if code != 0 or not re.fullmatch(r"[A-Za-z]+", kernel or ""):
        net = detect_network_device(run)
        if net:
            return net
        return {"family": "unknown", "os": "Unknown (no uname; unrecognised CLI)",
                "version": ""}
    if kernel == "FreeBSD":
        _, ver, _ = run("freebsd-version 2>/dev/null || uname -r")
        fw = detect_freebsd_firewall(run, ver)
        if fw:
            return fw
        return {"family": "freebsd", "os": "FreeBSD", "version": ver}

    _, osr, _ = run("cat /etc/os-release 2>/dev/null")
    fields = {}
    for line in osr.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            fields[k] = v.strip().strip('"')
    distro_id = fields.get("ID", "").lower()
    if distro_id not in ("ubuntu", "debian"):
        # Arista EOS (bash shell) is Linux underneath; identify it by its release file.
        _, eos, _ = run("cat /etc/Eos-release 2>/dev/null")
        if eos.strip():
            m = re.search(r"(\d+\.\d+\.\d+\S*)", eos)
            _, hw, _ = run("FastCli -c 'show version' 2>/dev/null | head -3")
            model = (re.search(r"Arista\s+(\S+)", hw) or [None, ""])[1]
            return _network_info("Arista", "Arista EOS", m.group(1) if m else "", model)
    pretty = fields.get("PRETTY_NAME") or fields.get("NAME", "Linux")
    version = fields.get("VERSION_ID", "")
    family = "ubuntu" if distro_id in ("ubuntu", "debian") else distro_id or "linux"
    return {"family": family, "os": pretty, "version": version}


def auth_policy(methods) -> str:
    if methods is None:
        return "unknown"
    if "none" in methods:
        return "no_auth_required"
    if "password" in methods or "keyboard-interactive" in methods:
        return "password_allowed"
    if "publickey" in methods:
        return "key_only"
    return "unknown"


def try_login(host, port, username, password, timeout):
    """One password login attempt on ONE connection (no pre-probe, so aggressive
    sshguard/blacklistd/MaxStartups setups don't see extra half-open sessions).
    Returns (kind, value): ("ok", client) | ("key_only", methods) |
    ("denied", None) | ("error", message). Transient connection errors are
    retried once after a short pause."""
    err = ""
    for attempt in (1, 2):
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            c.connect(
                hostname=host, port=port, username=username, password=password,
                timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                allow_agent=False, look_for_keys=False,
            )
            return "ok", c
        except paramiko.BadAuthenticationType as e:
            # Server doesn't offer password auth at all; it tells us what it does.
            c.close()
            return "key_only", list(e.allowed_types)
        except paramiko.AuthenticationException:
            c.close()
            return "denied", None
        except (socket.timeout, socket.error, paramiko.SSHException, OSError) as e:
            c.close()
            err = f"{type(e).__name__}: {e}"
            if attempt == 1:
                time.sleep(2)
    return "error", err


def port_open(host: str, port: int, timeout: float) -> bool:
    """Fast raw-socket check before attempting SSH."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_host(host, port, creds, timeout, cve_mod, mitigation=False,
              device_map=None) -> dict:
    """Always returns a record. 'state' says what happened to this IP."""
    result = {"host": host, "scanned_at": datetime.now(timezone.utc).isoformat(),
              "state": None}

    if not port_open(host, port, timeout):
        result["state"] = "port_closed"
        return result

    client = None
    key_only_methods: dict = {}     # username -> methods the server offered instead
    denied = False
    for username, password in creds:
        if username in key_only_methods:
            continue  # server told us password auth isn't offered for this user
        kind, val = try_login(host, port, username, password, timeout)
        if kind == "ok":
            client = val
            result["username"] = username  # which account worked (never the password)
            break
        if kind == "key_only":
            key_only_methods[username] = val
        elif kind == "denied":
            denied = True
        else:
            result["state"] = "ssh_error"
            result["error"] = val
            return result

    if client is not None:
        result["ssh_auth_policy"] = "password_allowed"
    elif key_only_methods and not denied:
        first = next(iter(key_only_methods.values()))
        result["ssh_auth_methods"] = first
        result["ssh_auth_policy"] = auth_policy(first)
        result["state"] = "key_only"
        return result
    else:
        result["ssh_auth_policy"] = "password_allowed" if denied else "unknown"
        result["state"] = "auth_failed"
        return result

    def run(cmd, timeout_=15):
        return ssh_exec(client, cmd, timeout_)

    try:
        osinfo = detect_os(run)
        if device_map and host in device_map:      # manual role override
            osinfo["role"] = device_map[host]
        result.update(osinfo)
        result["cve"] = cve_mod.CVE_ID
        skip = cvelib.not_applicable_reason(cve_mod, osinfo)
        if skip:
            na = {"status": "not_applicable", "details": [{"note": skip}]}
            result["cve_check"] = na
            if mitigation:
                result["mitigation"] = dict(na)
        else:
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


def load_creds_file(path: str, max_attempts: int) -> list[tuple[str, str]]:
    """Read [{"username":..., "password":...}, ...]. Refuses a file that other
    users can read or that someone else owns."""
    try:
        st = os.stat(path)
    except OSError as e:
        sys.exit(f"[!] Cannot read creds file {path}: {e}")
    if st.st_mode & 0o077:
        sys.exit(f"[!] {path} is accessible by other users "
                 f"(mode {oct(st.st_mode & 0o777)}). Run: chmod 600 {path}")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        sys.exit(f"[!] {path} is not owned by you; refusing to use it.")
    try:
        with open(path) as f:
            data = json.load(f)
        creds = [(c["username"], c["password"]) for c in data]
        assert creds and all(isinstance(u, str) and isinstance(p, str)
                             and u and p for u, p in creds)
    except (ValueError, KeyError, TypeError, AssertionError):
        sys.exit('[!] Creds file must be a non-empty JSON list of '
                 '{"username": "...", "password": "..."} objects.')
    return creds[:max_attempts]


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
    ap.add_argument("--username", "-u",
                    help="SSH username (single-credential mode). Not needed with "
                         "--creds-file.")
    ap.add_argument("--creds-file",
                    help="JSON list of {\"username\",\"password\"} pairs, tried in "
                         "order per host until one logs in. Must be chmod 600.")
    ap.add_argument("--max-attempts", type=int, default=3,
                    help="Max credential pairs tried per host (default 3) - "
                         "limits account lockouts / fail2ban / CSF LFD blocks.")
    ap.add_argument("--password-env", default="SSH_PASSWORD",
                    help="Env var holding the password (default: SSH_PASSWORD). "
                         "If unset, you'll be prompted.")
    ap.add_argument("--port", "-p", type=int, default=22)
    ap.add_argument("--workers", "-w", type=int, default=20)
    ap.add_argument("--timeout", "-t", type=int, default=8,
                    help="Per-connection/port timeout, seconds (default 8).")
    ap.add_argument("--output", "-o", default=None,
                    help="Output prefix. The CVE ID is always appended, so "
                         "'-o audit' -> audit_CVE-XXXX.{json,csv}. Default: "
                         "<CVE>_<subnet>_<date-time>, e.g. "
                         "CVE-2026-109518_66.196.48.0-25_20261111-125900.")
    ap.add_argument("--device-map",
                    help="JSON file {\"10.0.0.1\": \"router\", ...} to override the "
                         "inferred role (router/switch/firewall) of network devices.")
    ap.add_argument("--mitigation-check", action="store_true",
                    help="Also run the definition's mitigation_check() per host "
                         "(exposure/workaround posture, independent of patch status).")
    args = ap.parse_args()

    try:
        cve_mod = cvelib.load_cve(args.cve, args.cve_dir)
    except (FileNotFoundError, AttributeError) as e:
        sys.exit(f"[!] {e}")
    cve_id = cve_mod.CVE_ID
    subnet_list = [x.strip() for arg in args.subnet
                   for x in arg.split(",") if x.strip()]
    if args.output:
        out_stem = f"{args.output}_{cve_id}"
    else:
        # Auto name: <CVE>_<subnet>_<YYYYMMDD-HHMMSS>, so every run is a new version.
        tag = re.sub(r"[^A-Za-z0-9.]+", "-", subnet_list[0]).strip("-")
        if len(subnet_list) > 1:
            tag += f"+{len(subnet_list) - 1}more"
        out_stem = f"{cve_id}_{tag}_{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    if args.mitigation_check and not hasattr(cve_mod, "mitigation_check"):
        print(f"[!] {cve_id} has no mitigation_check(); --mitigation-check ignored.",
              file=sys.stderr)

    if args.creds_file:
        creds = load_creds_file(args.creds_file, max(1, args.max_attempts))
        who = f"{len(creds)} credential pair(s) from {args.creds_file}"
    else:
        if not args.username:
            sys.exit("[!] Provide --username or --creds-file.")
        password = os.environ.get(args.password_env)
        if not password:
            try:
                password = getpass.getpass(f"SSH password for {args.username}: ")
            except (KeyboardInterrupt, EOFError):
                sys.exit("\n[!] Cancelled at password prompt.")
        creds = [(args.username, password)]
        who = args.username

    device_map = None
    if args.device_map:
        try:
            with open(args.device_map) as f:
                device_map = json.load(f)
            assert isinstance(device_map, dict)
        except (OSError, ValueError, AssertionError) as e:
            sys.exit(f"[!] Bad --device-map {args.device_map}: {e}")

    targets = expand_targets(args.subnet)
    print(f"[*] {len(targets)} target(s). Checking port {args.port}, then auditing "
          f"for {cve_id} as {who} ({args.workers} workers)...",
          file=sys.stderr)

    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {
            ex.submit(scan_host, h, args.port, creds,
                      args.timeout, cve_mod, args.mitigation_check,
                      device_map): h
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
                print(f"[+] {res['host']:<16} {state:<12} {res.get('username',''):<10} {res.get('os','?'):<26} "
                      f"{res.get('version',''):<14} CVE:{status}{extra}", file=sys.stderr)
            elif state in ("ssh_error", "info_error", "auth_failed", "key_only"):
                print(f"[-] {res['host']:<16} {state}"
                      + (f"  ({res['error']})" if res.get("error") else ""),
                      file=sys.stderr)
            # port_closed: silent on screen

    def sort_key(r):
        h = r["host"]
        try:
            return (0, tuple(int(x) for x in h.split(".")))
        except ValueError:
            return (1, (h,))
    results.sort(key=sort_key)

    json_path = f"{out_stem}.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)

    csv_path = f"{out_stem}.csv"
    with open(csv_path, "w", newline="") as f:
        wr = csv.writer(f)
        header = ["host", "state", "username", "os", "version", "family",
                  "vendor", "model", "role", "ssh_auth_policy",
                  "cve", "cve_status", "details"]
        if args.mitigation_check:
            header += ["mitigation_status", "mitigation_details"]
        wr.writerow(header)
        for r in results:
            cc = r.get("cve_check", {})
            row = [
                r["host"], r.get("state", ""), r.get("username", ""), r.get("os", ""), r.get("version", ""),
                r.get("family", ""), r.get("vendor", ""), r.get("model", ""),
                r.get("role", ""), r.get("ssh_auth_policy", ""), r.get("cve", "") if r.get("state") == "logged_in" else "",
                cc.get("status", ""), json.dumps(cc.get("details", [])) if cc else "",
            ]
            if args.mitigation_check:
                mit = r.get("mitigation", {})
                row += [mit.get("status", ""),
                        json.dumps(mit.get("details", [])) if mit else ""]
            wr.writerow(row)

    # Scan metadata sidecar (subnet(s) scanned) for the report.
    meta_path = f"{out_stem}.meta.json"
    with open(meta_path, "w") as f:
        json.dump({"cve": cve_id,
                   "subnets": subnet_list,
                   "port": args.port,
                   "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds")},
                  f, indent=2)

    # Remediation sidecar for the report (comes from the CVE definition).
    rem_path = None
    remediation = getattr(cve_mod, "REMEDIATION", "")
    if remediation.strip():
        rem_path = f"{out_stem}.remediation.md"
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
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupted.")