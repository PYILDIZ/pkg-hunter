"""Terminal and Markdown output."""

from __future__ import annotations

from datetime import datetime, timezone

from .analyzer import ScanResult


def one_line(r: ScanResult) -> str:
    tag = {"likely-malicious": "!!", "suspicious": "! ", "removed": "x ", "error": "? "}.get(r.verdict, "  ")
    top = ", ".join(f.rule for f in r.findings[:4])
    squat = f" [looks like '{r.squat.target}']" if r.squat else ""
    return f"{tag} {r.score:5.1f}  {r.name} {r.version or ''}{squat}  {top}".rstrip()


def detail(r: ScanResult) -> str:
    lines = [f"{r.name} {r.version or ''}  ->  {r.verdict.upper()} (score {r.score})", r.url]
    if r.squat:
        lines.append(f"  name imitates '{r.squat.target}' (popularity rank #{r.squat.target_rank + 1}, "
                     f"{r.squat.technique})")
    for f in r.findings:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        lines.append(f"  [{f.weight:>4.1f}] {f.rule}: {f.title}")
        lines.append(f"         {loc}")
        if f.snippet:
            lines.append(f"         > {f.snippet}")
    lines.append(f"  artifacts: {', '.join(r.artifacts) or 'none'}  |  text files scanned: {r.files_scanned}")
    if r.error:
        lines.append(f"  errors: {r.error}")
    return "\n".join(lines)


def report_draft(r: ScanResult) -> str:
    """Evidence summary in a form you can paste into PyPI's malware report."""
    parts = [f"Project {r.name} {r.version or ''} appears to be malicious."]
    if r.squat:
        parts.append(f"Its name imitates the popular package '{r.squat.target}' ({r.squat.technique}).")
    for f in r.findings:
        if f.line:
            parts.append(f"- {f.title}: {f.path} line {f.line}: `{f.snippet}`")
        elif f.path not in ("<combined>",):
            parts.append(f"- {f.title}")
    parts.append("Found by static analysis only; the package was not installed or executed.")
    return "\n".join(parts)


def markdown(results: list[ScanResult], counts: dict[str, int]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = sum(counts.values())
    out = [f"# pkg-hunter report ({now})", "",
           f"Packages scanned: **{total}**", ""]
    out += [f"- {v}: {n}" for v, n in sorted(counts.items(), key=lambda kv: -kv[1])]
    out += ["", "## Flagged packages", "",
            "| Score | Verdict | Package | Lookalike of | Top signals |",
            "|---:|---|---|---|---|"]
    for r in results:
        sig = ", ".join(f.rule for f in r.findings[:4])
        out.append(f"| {r.score} | {r.verdict} | [{r.name} {r.version or ''}]({r.url}) | "
                   f"{r.squat.target if r.squat else ''} | {sig} |")
    out += ["", "## Evidence", ""]
    for r in results:
        out += [f"### {r.name} {r.version or ''}", "", "```text", detail(r), "```", "",
                "<details><summary>Report draft for PyPI</summary>", "", report_draft(r), "", "</details>", ""]
    return "\n".join(out)
