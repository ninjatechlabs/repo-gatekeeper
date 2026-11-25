"""8-domain report aggregator, verdict engine, Markdown renderer, and safe export gate."""

from __future__ import annotations

import shutil
from pathlib import Path

from .models import DOMAINS, DomainSummary, Finding, ScanResult, Verdict


def build_domain_summaries(findings: list[Finding]) -> list[DomainSummary]:
    """Aggregate findings into the 8 security domains."""
    buckets: dict[str, list[Finding]] = {d: [] for d in DOMAINS}
    for f in findings:
        target = f.domain if f.domain in buckets else "Application & Runtime Vulnerabilities"
        buckets[target].append(f)

    summaries: list[DomainSummary] = []
    for domain in DOMAINS:
        items = buckets[domain]
        crit = sum(1 for x in items if x.severity == "CRITICAL")
        high = sum(1 for x in items if x.severity == "HIGH")
        med = sum(1 for x in items if x.severity == "MEDIUM")
        low = sum(1 for x in items if x.severity == "LOW")
        info = sum(1 for x in items if x.severity == "INFO")

        if crit > 0 or high > 0:
            status = "FAIL"
        elif med > 0 or low > 0:
            status = "WARN"
        else:
            status = "PASS"

        summaries.append(
            DomainSummary(
                domain=domain,
                status=status,  # type: ignore[arg-type]
                total=len(items),
                critical=crit,
                high=high,
                medium=med,
                low=low,
                info=info,
            )
        )
    return summaries


def compute_verdict(findings: list[Finding]) -> Verdict:
    """Determine overall installation verdict from aggregated findings."""
    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    high = sum(1 for f in findings if f.severity == "HIGH")
    med = sum(1 for f in findings if f.severity == "MEDIUM")

    if crit > 0 or high >= 3:
        return "DO NOT INSTALL"
    if high > 0 or med > 0:
        return "SAFE WITH MODIFICATIONS"
    return "SAFE TO INSTALL"


def render_markdown_report(scan: ScanResult) -> str:
    """Render a complete Markdown security audit report."""
    lines = [
        f"# Repo Gatekeeper Security Audit: `{scan.repo_name}`",
        "",
        f"- **Repository:** {scan.repo_url}",
        f"- **Scan ID:** `{scan.scan_id}`",
        f"- **Verdict:** **{scan.verdict or 'PENDING'}**",
        f"- **Local LLM Status:** `{scan.llm_status}`",
        f"- **Completed At:** {scan.completed_at or 'N/A'}",
        "",
    ]

    if scan.llm_summary:
        lines.extend(["## Local LLM Adversarial Summary", "", scan.llm_summary, ""])

    lines.extend(
        [
            "## 8-Domain Summary",
            "",
            "| Domain | Status | Critical | High | Medium | Low | Info |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
    )
    for d in scan.domains:
        lines.append(
            f"| {d.domain} | **{d.status}** | {d.critical} | {d.high} | {d.medium} | {d.low} | {d.info} |"
        )

    lines.extend(["", f"## Detailed Findings ({len(scan.findings)})", ""])
    if not scan.findings:
        lines.append("No security findings were detected.")
    else:
        for idx, f in enumerate(scan.findings, start=1):
            loc = f"`{f.file_path}`" + (f":{f.line_number}" if f.line_number else "") if f.file_path else "N/A"
            lines.extend(
                [
                    f"### {idx}. [{f.severity}] {f.title}",
                    f"- **Domain:** {f.domain}",
                    f"- **Source:** `{f.source}`",
                    f"- **Location:** {loc}",
                    f"- **Description:** {f.description}",
                ]
            )
            if f.snippet:
                lines.append(f"- **Snippet:** `{f.snippet}`")
            lines.extend([f"- **Remediation:** {f.remediation}", ""])

    return "\n".join(lines)


def export_clean_repo(scan_repo_dir: Path, approved_root: Path, repo_name: str) -> Path:
    """Strip .git and copy the audited repository to approved_root/repo_name."""
    if not scan_repo_dir.is_dir():
        raise FileNotFoundError("Scanned repository directory no longer exists.")

    approved_root.mkdir(parents=True, exist_ok=True)
    safe_name = repo_name.replace("/", "__").replace("..", "_")
    dest = approved_root / safe_name

    if dest.exists():
        shutil.rmtree(dest)

    shutil.copytree(
        scan_repo_dir,
        dest,
        ignore=shutil.ignore_patterns(".git"),
        symlinks=False,
    )
    return dest
