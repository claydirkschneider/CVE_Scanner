"""
Shared library for the CVE scanner.

Holds the remote version helpers that CVE definition modules use, and the loader
that finds a CVE definition file by its ID. The scanner (cve_scan.py) and the
report (make_report.py) both import from here, so CVE definitions never need to
touch the scanner itself.

A CVE definition module (in the cves/ directory, named CVE_YYYY_NNNNN.py) must
provide:
    CVE_ID        str, e.g. "CVE-2026-109518"
    cve_check(run, osinfo) -> {"status": str, "details": list}
and may provide:
    mitigation_check(run, osinfo) -> {"status": str, "details": list}
    REMEDIATION   str (markdown) — the known fix, shown in the report
    APPLIES_TO    set of osinfo families the CVE can affect, e.g. {"ubuntu",
                  "debian","linux","freebsd"}. If present, the scanner marks any
                  other host not_applicable WITHOUT calling cve_check. Network
                  appliances (switches/routers/firewalls) have family "network",
                  so they are skipped unless "network" is listed. If absent, only
                  network appliances are skipped.

Contract for the two callables:
    run(cmd, timeout=15) -> (exit_code, stdout, stderr)   # runs on the host
    osinfo -> {"family": "ubuntu"|"debian"|"freebsd"|..., "os": str, "version": str}
    return status one of: vulnerable | ok | not_applicable | review | error
      (mitigation_check uses: mitigated | not_mitigated | not_applicable | review | error)
"""

from __future__ import annotations

import importlib.util
import os
import sys


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
    """True if installed < fixed, compared with the host's NATIVE tooling."""
    if family in ("ubuntu", "debian"):
        code, _, _ = run(f"dpkg --compare-versions '{installed}' lt '{fixed}'")
        return code == 0  # exit 0 == comparison true
    if family == "freebsd":
        _, out, _ = run(f"pkg version -t '{installed}' '{fixed}'")
        return out.strip() == "<"
    return False


def not_applicable_reason(cve_mod, osinfo: dict) -> str | None:
    """Return a human reason if this CVE should be skipped for this host, else None."""
    family = osinfo.get("family", "")
    allowed = getattr(cve_mod, "APPLIES_TO", None)
    if family == "network":
        if allowed and "network" in allowed:
            return None
        who = " ".join(x for x in (osinfo.get("vendor"), osinfo.get("model")) if x)
        base = f"; built on {osinfo['base_os']}" if osinfo.get("base_os") else ""
        return (f"network appliance ({who or osinfo.get('os', 'unknown')}, "
                f"role: {osinfo.get('role', 'unknown')}{base}) - host-OS CVE check "
                f"not applicable; confirm against the vendor advisory"
                f"{' (appliance base-OS fixes ship in vendor releases)' if base else ''}")
    if allowed is not None and family not in allowed:
        return f"{osinfo.get('os', family)} is outside this CVE's scope"
    return None


def cve_module_path(cve_id: str, cve_dir: str) -> str:
    """cves/CVE-2026-109518  ->  <cve_dir>/CVE_2026_109518.py"""
    return os.path.join(cve_dir, cve_id.replace("-", "_") + ".py")


def load_cve(cve_id: str, cve_dir: str):
    """Import and return the CVE definition module for cve_id from cve_dir."""
    path = cve_module_path(cve_id, cve_dir)
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"No CVE definition for {cve_id} at {path}. "
            f"Add {os.path.basename(path)} to {cve_dir}/.")

    # Make sure this library is importable from inside the CVE module
    # (it does `from cvelib import installed_version, version_less_than`).
    libdir = os.path.dirname(os.path.abspath(__file__))
    if libdir not in sys.path:
        sys.path.insert(0, libdir)

    spec = importlib.util.spec_from_file_location(
        os.path.basename(path)[:-3], path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    for attr in ("CVE_ID", "cve_check"):
        if not hasattr(mod, attr):
            raise AttributeError(f"{path} is missing required '{attr}'")
    return mod