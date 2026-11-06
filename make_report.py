#!/usr/bin/env python3
"""
Build an executive remediation report (HTML) from cve_scan.py JSON output.

Title is the CVE. Headline verdict is designed to show, after fixes are in,
that the CVE is remediated across the audited fleet.

Usage:
    python3 make_report.py audit.json
    python3 make_report.py audit.json -o cve_report.html --org "Acme Infra" \
        --prepared-by "J. Smith"
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime

# --- Design tokens (from the house data-viz status palette, light surface) ---
C = {
    "good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a",
    "critical": "#d03b3b",
    "surface": "#fcfcfb", "plane": "#f9f9f7",
    "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#898781",
    "grid": "#e1e0d9", "baseline": "#c3c2b7", "success_text": "#006300",
}

# CVE-check statuses we treat as "assessed"
ASSESSED = {"vulnerable", "ok", "review", "not_applicable", "error"}


def esc(x) -> str:
    return html.escape("" if x is None else str(x))


def _inline(text: str) -> str:
    """Escape, then re-apply `code` spans and [text](url) links."""
    out = esc(text)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\[([^\]]+)\]\((https?://[^\s)]+)\)",
                 r'<a href="\2">\1</a>', out)
    # bare URLs
    out = re.sub(r"(?<![\">])(https?://[^\s<]+)", r'<a href="\1">\1</a>', out)
    return out


def render_md(text: str) -> str:
    """Tiny markdown-lite -> HTML: #/##/### headings, - bullets, ``` code, links."""
    lines = text.replace("\r\n", "\n").split("\n")
    html_parts, in_code, in_list, para = [], False, False, []

    def flush_para():
        if para:
            html_parts.append(f"<p>{' '.join(_inline(p) for p in para)}</p>")
            para.clear()

    def close_list():
        nonlocal in_list
        if in_list:
            html_parts.append("</ul>")
            in_list = False

    for ln in lines:
        if ln.strip().startswith("```"):
            flush_para(); close_list()
            if in_code:
                html_parts.append("</code></pre>"); in_code = False
            else:
                html_parts.append('<pre><code>'); in_code = True
            continue
        if in_code:
            html_parts.append(esc(ln))
            continue
        if not ln.strip():
            flush_para(); close_list(); continue
        m = re.match(r"(#{1,3})\s+(.*)", ln)
        if m:
            flush_para(); close_list()
            html_parts.append(f"<h4>{_inline(m.group(2))}</h4>")
            continue
        if re.match(r"\s*[-*]\s+", ln):
            flush_para()
            if not in_list:
                html_parts.append("<ul>"); in_list = True
            html_parts.append(f"<li>{_inline(re.sub(r'^\s*[-*]\s+', '', ln))}</li>")
            continue
        para.append(ln.strip())
    flush_para(); close_list()
    if in_code:
        html_parts.append("</code></pre>")
    return "\n".join(html_parts)


def summarize_details(cc: dict) -> str:
    """One-line human summary of a host's cve_check details."""
    details = cc.get("details") or []
    if not details:
        return ""
    d = details[0] if isinstance(details[0], dict) else {"note": details[0]}
    if "installed_pkg_version" in d or "kernel" in d:
        parts = []
        if d.get("kernel"):
            parts.append(f"kernel {d['kernel']}")
        if d.get("installed_pkg_version"):
            parts.append(f"pkg {d['installed_pkg_version']}")
        if d.get("fixed_version"):
            parts.append(f"fixed ≥ {d['fixed_version']}")
        if d.get("mptcp_listener_possible"):
            parts.append("MPTCP enabled")
        return ", ".join(parts)
    if d.get("freebsd_version"):
        s = d["freebsd_version"]
        return f"{s}" + (f", fixed ≥ {d['fixed_version']}" if d.get("fixed_version") else "")
    if d.get("note"):
        return str(d["note"])
    return ", ".join(f"{k}={v}" for k, v in d.items())


def build(records: list[dict], cve: str, org: str, prepared_by: str,
          fix_html: str = "") -> str:
    total = len(records)
    states = Counter(r.get("state", "unknown") for r in records)
    audited = [r for r in records if r.get("state") == "logged_in"]

    cve_status = Counter()
    for r in audited:
        st = (r.get("cve_check") or {}).get("status", "unknown")
        cve_status[st] += 1

    n_vuln = cve_status.get("vulnerable", 0)
    n_ok = cve_status.get("ok", 0)
    n_review = cve_status.get("review", 0)
    n_na = cve_status.get("not_applicable", 0)
    n_err = cve_status.get("error", 0)

    # Verdict
    if n_vuln > 0:
        verdict_role, icon = "critical", "✕"
        headline = f"NOT REMEDIATED — {n_vuln} host(s) still vulnerable"
        sub = "Remediation is incomplete. See the vulnerable hosts below."
    elif n_review > 0 or n_err > 0:
        verdict_role, icon = "warning", "!"
        headline = f"0 vulnerable — {n_review + n_err} host(s) need manual review"
        sub = ("No host is confirmed vulnerable, but some could not be confirmed "
               "patched. Resolve the review items for a clean result.")
    else:
        verdict_role, icon = "good", "✓"
        headline = "REMEDIATED — 0 vulnerable across all audited hosts"
        sub = "Every host that was audited is confirmed not vulnerable."

    verdict_color = C[verdict_role]

    os_counts = Counter(r.get("os", "unknown") for r in audited)

    # Severity order for the host table
    order = {"vulnerable": 0, "error": 1, "review": 2, "ok": 3, "not_applicable": 4}

    def host_sort(r):
        st = (r.get("cve_check") or {}).get("status", "unknown")
        h = r.get("host", "")
        try:
            ip = tuple(int(x) for x in h.split("."))
        except ValueError:
            ip = (999, h)
        return (order.get(st, 9), ip)

    rows = []
    for r in sorted(audited, key=host_sort):
        cc = r.get("cve_check") or {}
        st = cc.get("status", "unknown")
        badge = {"vulnerable": "critical", "error": "serious",
                 "review": "warning", "ok": "good",
                 "not_applicable": "muted"}.get(st, "muted")
        rows.append(f"""
          <tr>
            <td class="mono">{esc(r.get('host'))}</td>
            <td>{esc(r.get('os'))}</td>
            <td class="mono">{esc(r.get('version'))}</td>
            <td><span class="pill {badge}">{esc(st)}</span></td>
            <td class="note">{esc(summarize_details(cc))}</td>
          </tr>""")
    host_rows = "".join(rows) or (
        '<tr><td colspan="5" class="note">No hosts were logged into.</td></tr>')

    os_rows = "".join(
        f"<tr><td>{esc(os)}</td><td class='mono'>{n}</td></tr>"
        for os, n in sorted(os_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ) or '<tr><td colspan="2" class="note">—</td></tr>'

    generated = datetime.now().strftime("%Y-%m-%d %H:%M %Z").strip()
    meta_bits = []
    if org:
        meta_bits.append(esc(org))
    if prepared_by:
        meta_bits.append("Prepared by " + esc(prepared_by))
    meta_bits.append("Generated " + esc(generated))
    meta_line = " &nbsp;·&nbsp; ".join(meta_bits)

    def tile(label, value, role=None):
        col = C.get(role, C["ink"]) if role else C["ink"]
        return f"""<div class="tile">
            <div class="tile-val" style="color:{col}">{value}</div>
            <div class="tile-lbl">{esc(label)}</div></div>"""

    tiles = "".join([
        tile("IPs in scope", total),
        tile("Hosts audited", len(audited)),
        tile("Vulnerable", n_vuln, "critical" if n_vuln else None),
        tile("Patched / not affected", n_ok + n_na, "good" if (n_ok + n_na) else None),
        tile("Needs review", n_review + n_err, "warning" if (n_review + n_err) else None),
    ])

    fix_section = ""
    if fix_html:
        fix_section = f"""
  <h3>Known fix &amp; remediation</h3>
  <div class="fixbox">{fix_html}</div>"""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(cve)} — Remediation Report</title>
<style>
  :root {{
    --good:{C['good']}; --warning:{C['warning']}; --serious:{C['serious']};
    --critical:{C['critical']}; --surface:{C['surface']}; --plane:{C['plane']};
    --ink:{C['ink']}; --ink2:{C['ink2']}; --muted:{C['muted']};
    --grid:{C['grid']};
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:var(--plane); color:var(--ink);
    font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:900px; margin:0 auto; padding:40px 28px 64px; }}
  .eyebrow {{ color:var(--muted); font-size:12px; letter-spacing:.14em;
    text-transform:uppercase; }}
  h1 {{ font-size:34px; margin:4px 0 2px; letter-spacing:-.01em; }}
  .subtitle {{ color:var(--ink2); font-size:16px; margin:0 0 6px; }}
  .meta {{ color:var(--muted); font-size:13px; margin-bottom:28px; }}
  .verdict {{ border-radius:14px; padding:22px 24px; margin:0 0 28px;
    color:#fff; display:flex; align-items:center; gap:18px; }}
  .verdict .mark {{ width:44px; height:44px; border-radius:50%;
    background:rgba(255,255,255,.22); display:flex; align-items:center;
    justify-content:center; font-size:24px; font-weight:700; flex:0 0 auto; }}
  .verdict h2 {{ margin:0 0 2px; font-size:20px; }}
  .verdict p {{ margin:0; font-size:14px; opacity:.92; }}
  .tiles {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px;
    margin-bottom:34px; }}
  .tile {{ background:var(--surface); border:1px solid var(--grid);
    border-radius:12px; padding:16px 14px; text-align:center; }}
  .tile-val {{ font-size:30px; font-weight:700; letter-spacing:-.02em; }}
  .tile-lbl {{ color:var(--ink2); font-size:12px; margin-top:4px; }}
  h3 {{ font-size:13px; letter-spacing:.08em; text-transform:uppercase;
    color:var(--muted); margin:30px 0 10px; }}
  table {{ width:100%; border-collapse:collapse; background:var(--surface);
    border:1px solid var(--grid); border-radius:12px; overflow:hidden; }}
  th,td {{ text-align:left; padding:10px 14px; border-bottom:1px solid var(--grid);
    font-size:14px; vertical-align:top; }}
  th {{ color:var(--ink2); font-size:12px; letter-spacing:.04em;
    text-transform:uppercase; background:#fbfbf9; }}
  tr:last-child td {{ border-bottom:none; }}
  .mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    font-size:13px; }}
  .note {{ color:var(--ink2); font-size:13px; }}
  .pill {{ display:inline-block; padding:2px 9px; border-radius:999px;
    font-size:12px; font-weight:600; color:#fff; }}
  .pill.good {{ background:var(--good); }}
  .pill.warning {{ background:var(--warning); color:#0b0b0b; }}
  .pill.serious {{ background:var(--serious); }}
  .pill.critical {{ background:var(--critical); }}
  .pill.muted {{ background:#d9d8d2; color:#52514e; }}
  .cols {{ display:grid; grid-template-columns:1fr 1fr; gap:24px; align-items:start; }}
  .legend {{ color:var(--ink2); font-size:13px; line-height:1.7; margin-top:8px; }}
  .fixbox {{ background:var(--surface); border:1px solid var(--grid);
    border-left:4px solid var(--good); border-radius:12px; padding:4px 20px 14px; }}
  .fixbox h4 {{ font-size:14px; margin:18px 0 6px; color:var(--ink); }}
  .fixbox p {{ margin:8px 0; color:var(--ink2); font-size:14px; }}
  .fixbox ul {{ margin:8px 0; padding-left:20px; color:var(--ink2); font-size:14px; }}
  .fixbox li {{ margin:3px 0; }}
  .fixbox pre {{ background:#f4f4f1; border:1px solid var(--grid); border-radius:8px;
    padding:12px 14px; overflow-x:auto; font-size:13px; }}
  .fixbox code {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
  .fixbox pre code {{ white-space:pre; }}
  .fixbox a {{ color:#1c5cab; }}
  footer {{ color:var(--muted); font-size:12px; margin-top:36px;
    border-top:1px solid var(--grid); padding-top:16px; }}
  @media print {{
    body {{ background:#fff; }}
    .verdict {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
    .tile,table,th {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  }}
  @media (max-width:680px) {{ .tiles{{grid-template-columns:repeat(2,1fr);}}
    .cols{{grid-template-columns:1fr;}} }}
</style></head>
<body><div class="wrap">
  <div class="eyebrow">Vulnerability Remediation Report</div>
  <h1>{esc(cve)}</h1>
  <p class="subtitle">Linux kernel / fleet exposure audit</p>
  <div class="meta">{meta_line}</div>

  <div class="verdict" style="background:{verdict_color}">
    <div class="mark">{icon}</div>
    <div><h2>{esc(headline)}</h2><p>{esc(sub)}</p></div>
  </div>

  <div class="tiles">{tiles}</div>
{fix_section}
  <div class="cols">
    <div>
      <h3>Hosts by operating system (audited)</h3>
      <table><thead><tr><th>Operating system</th><th>Hosts</th></tr></thead>
        <tbody>{os_rows}</tbody></table>
    </div>
    <div>
      <h3>What the statuses mean</h3>
      <div class="legend">
        <span class="pill critical">vulnerable</span> affected and unpatched<br>
        <span class="pill good">ok</span> confirmed patched by version<br>
        <span class="pill muted">not_applicable</span> this OS isn't affected<br>
        <span class="pill warning">review</span> couldn't confirm — follow up<br>
        <span class="pill serious">error</span> data gathering failed
      </div>
    </div>
  </div>

  <h3>Host detail (audited hosts)</h3>
  <table>
    <thead><tr><th>Host</th><th>OS</th><th>Version</th><th>Status</th>
      <th>Evidence</th></tr></thead>
    <tbody>{host_rows}</tbody>
  </table>

  <footer>
    Scope: {total} IP(s) scanned
    ({', '.join(f'{esc(k)}: {v}' for k, v in sorted(states.items()))}).
    Only hosts that could be logged into are assessed for the CVE.
    “review” is not a clean result — it marks hosts that must be confirmed
    manually against the vendor advisory.
  </footer>
</div></body></html>"""


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Build an executive HTML remediation report from scan JSON.")
    ap.add_argument("json", help="JSON file produced by cve_scan.py")
    ap.add_argument("--output", "-o", help="Output HTML (default: <input>_report.html)")
    ap.add_argument("--cve", help="Override the CVE title (else taken from the data)")
    ap.add_argument("--org", default="", help="Organization name for the header")
    ap.add_argument("--prepared-by", default="", help="Name for the header byline")
    ap.add_argument("--fix-file", help="Markdown file with the known fix / remediation "
                    "(defaults to remediation.md next to the data, if present)")
    ap.add_argument("--fix", help="Inline remediation text (overrides --fix-file)")
    args = ap.parse_args()

    try:
        with open(args.json) as f:
            records = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"Could not read {args.json}: {e}")
    if not isinstance(records, list):
        sys.exit("Expected a JSON list of host records (cve_scan.py output).")

    cve = args.cve or next(
        (r.get("cve") for r in records if r.get("cve")), "CVE")

    # Resolve the remediation text: --fix, else --fix-file, else a sibling
    # remediation.md if one exists. Rendered as a section when non-empty.
    fix_md = ""
    if args.fix:
        fix_md = args.fix
    else:
        fix_path = args.fix_file
        if not fix_path:
            sibling = os.path.join(os.path.dirname(os.path.abspath(args.json)),
                                   "remediation.md")
            fix_path = sibling if os.path.exists(sibling) else None
        if fix_path:
            try:
                with open(fix_path) as f:
                    fix_md = f.read()
            except OSError as e:
                print(f"[!] Could not read fix file {fix_path}: {e}", file=sys.stderr)
    fix_html = render_md(fix_md) if fix_md.strip() else ""

    out = args.output or (args.json.rsplit(".", 1)[0] + "_report.html")
    html_doc = build(records, cve, args.org, args.prepared_by, fix_html)
    with open(out, "w") as f:
        f.write(html_doc)

    audited = sum(1 for r in records if r.get("state") == "logged_in")
    vuln = sum(1 for r in records
               if (r.get("cve_check") or {}).get("status") == "vulnerable")
    print(f"[*] {cve}: {len(records)} IP(s), {audited} audited, {vuln} vulnerable.",
          file=sys.stderr)
    print(f"[*] Wrote {out} — open in a browser, or print to PDF to share.",
          file=sys.stderr)


if __name__ == "__main__":
    main()