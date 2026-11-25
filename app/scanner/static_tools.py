"""Deterministic static security scanners: Semgrep CE, Trivy, and Gitleaks."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import uuid
from pathlib import Path

from .models import Finding


async def _run_cmd(cmd: list[str], cwd: Path | None = None, timeout: int = 300) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["SEMGREP_SEND_METRICS"] = "off"

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return -1, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"

    return (
        proc.returncode if proc.returncode is not None else -1,
        stdout_b.decode("utf-8", errors="replace"),
        stderr_b.decode("utf-8", errors="replace"),
    )


def _rel(path_str: str | None, root: Path) -> str | None:
    if not path_str:
        return None
    try:
        return str(Path(path_str).resolve().relative_to(root.resolve())).replace("\\", "/")
    except Exception:
        return path_str.replace("\\", "/")


def _map_semgrep_domain(check_id: str, message: str) -> str:
    text = f"{check_id} {message}".lower()
    if any(k in text for k in ("docker", "container", "privileged", "kubernetes")):
        return "Container & Sandbox Escape Risks"
    if any(k in text for k in ("secret", "api-key", "apikey", "password", "token", "private-key")):
        return "Hardcoded Secrets & Poisoned AI Prompts"
    if any(k in text for k in ("eval", "exec", "obfuscat", "base64", "pickle", "deserializ")):
        return "Malicious Payloads & Obfuscation"
    if any(k in text for k in ("ssrf", "requests", "urllib", "exfil", "socket")):
        return "Data Exfiltration & Network Activity"
    if any(k in text for k in ("chmod", "setuid", "sudo", "path-traversal", "symlink")):
        return "File System & Privilege Escalation"
    return "Application & Runtime Vulnerabilities"


def _map_semgrep_severity(sev: str) -> str:
    s = (sev or "").upper()
    if s == "ERROR":
        return "HIGH"
    if s == "WARNING":
        return "MEDIUM"
    return "LOW"


async def run_semgrep(target_dir: Path) -> tuple[list[Finding], str]:
    """Run Semgrep CE on target_dir and return findings + status string."""
    if not shutil.which("semgrep"):
        return [], "semgrep binary not found"

    rc, out, err = await _run_cmd(
        ["semgrep", "scan", "--config", "auto", "--json", "--quiet", str(target_dir)],
        timeout=300,
    )
    findings: list[Finding] = []

    if not out.strip():
        return findings, f"semgrep exited {rc}: {err.strip()[:200]}"

    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        return findings, f"semgrep JSON parse error: {exc}"

    for res in data.get("results", []):
        check_id = res.get("check_id", "semgrep-rule")
        extra = res.get("extra", {})
        message = extra.get("message", "Semgrep security finding")
        sev = _map_semgrep_severity(extra.get("severity", "WARNING"))
        start = res.get("start", {})
        lines = extra.get("lines", "")
        if lines == "requires login":
            lines = ""

        findings.append(
            Finding(
                id=f"semgrep-{uuid.uuid4().hex[:8]}",
                domain=_map_semgrep_domain(check_id, message),
                severity=sev,  # type: ignore[arg-type]
                source="semgrep",
                title=check_id.split(".")[-1],
                description=message,
                file_path=_rel(res.get("path"), target_dir),
                line_number=start.get("line"),
                snippet=lines[:300] if lines else None,
                remediation=f"Review rule '{check_id}' and remediate the flagged pattern.",
            )
        )

    return findings, f"ok ({len(findings)} findings)"


def _map_trivy_severity(sev: str) -> str:
    s = (sev or "").upper()
    if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        return s
    return "MEDIUM"


async def run_trivy(target_dir: Path) -> tuple[list[Finding], str]:
    """Run Trivy filesystem scan for vulnerabilities and misconfigurations."""
    if not shutil.which("trivy"):
        return [], "trivy binary not found"

    rc, out, err = await _run_cmd(
        [
            "trivy",
            "fs",
            "--scanners",
            "vuln,misconfig",
            "--include-dev-deps",
            "--format",
            "json",
            "--quiet",
            str(target_dir),
        ],
        timeout=300,
    )
    findings: list[Finding] = []
    if not out.strip():
        return findings, f"trivy exited {rc}: {err.strip()[:200]}"

    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        return findings, f"trivy JSON parse error: {exc}"

    for result in data.get("Results", []):
        target_file = _rel(result.get("Target"), target_dir) or result.get("Target")

        for vuln in result.get("Vulnerabilities", []) or []:
            cve = vuln.get("VulnerabilityID", "CVE")
            pkg = vuln.get("PkgName", "unknown")
            installed = vuln.get("InstalledVersion", "?")
            fixed = vuln.get("FixedVersion", "none")
            title = vuln.get("Title") or f"{cve} in {pkg}"
            desc = vuln.get("Description") or f"Vulnerable package {pkg} ({installed})."

            findings.append(
                Finding(
                    id=f"trivy-vuln-{uuid.uuid4().hex[:8]}",
                    domain="Supply Chain, Dependencies & Submodules",
                    severity=_map_trivy_severity(vuln.get("Severity", "MEDIUM")),  # type: ignore[arg-type]
                    source="trivy",
                    title=f"{cve}: {pkg} ({installed})",
                    description=desc[:400],
                    file_path=target_file,
                    snippet=f"Installed: {installed} | Fixed in: {fixed}",
                    remediation=f"Upgrade {pkg} to {fixed}." if fixed != "none" else f"Review {cve} impact on {pkg}.",
                )
            )

        for mis in result.get("Misconfigurations", []) or []:
            mis_id = mis.get("ID", "MISCONFIG")
            title = mis.get("Title") or mis_id
            desc = mis.get("Description") or mis.get("Message") or "Misconfiguration detected."
            cause = mis.get("CauseMetadata", {})
            start_line = cause.get("StartLine")
            domain = (
                "Container & Sandbox Escape Risks"
                if any(k in (target_file or "").lower() for k in ("docker", "compose", "k8s", "helm"))
                else "File System & Privilege Escalation"
            )
            findings.append(
                Finding(
                    id=f"trivy-mis-{uuid.uuid4().hex[:8]}",
                    domain=domain,
                    severity=_map_trivy_severity(mis.get("Severity", "MEDIUM")),  # type: ignore[arg-type]
                    source="trivy",
                    title=f"{mis_id}: {title}",
                    description=desc[:400],
                    file_path=target_file,
                    line_number=start_line,
                    remediation=mis.get("Resolution") or "Fix the flagged configuration.",
                )
            )

    return findings, f"ok ({len(findings)} findings)"


def _redact_secret(val: str) -> str:
    if not val:
        return "***"
    if len(val) <= 8:
        return "*" * len(val)
    return f"{val[:4]}...{val[-2:]}"


async def run_gitleaks(target_dir: Path, report_path: Path) -> tuple[list[Finding], str]:
    """Run Gitleaks directory scan for hardcoded secrets."""
    if not shutil.which("gitleaks"):
        return [], "gitleaks binary not found"

    rc, _, err = await _run_cmd(
        [
            "gitleaks",
            "dir",
            "--no-banner",
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            str(target_dir),
        ],
        timeout=180,
    )
    findings: list[Finding] = []
    # gitleaks exits 0 (no leaks) or 1 (leaks found)
    if rc not in (0, 1):
        return findings, f"gitleaks exited {rc}: {err.strip()[:200]}"

    if not report_path.is_file():
        return findings, "ok (0 findings)"

    try:
        raw = report_path.read_text(encoding="utf-8", errors="replace").strip()
        items = json.loads(raw) if raw else []
    except Exception as exc:
        return findings, f"gitleaks JSON parse error: {exc}"

    for item in items or []:
        rule_id = item.get("RuleID", "secret")
        desc = item.get("Description", "Hardcoded secret detected")
        secret = _redact_secret(item.get("Secret", ""))
        sev = "CRITICAL" if any(k in rule_id.lower() for k in ("private-key", "aws", "github", "stripe", "gcp")) else "HIGH"

        findings.append(
            Finding(
                id=f"gitleaks-{uuid.uuid4().hex[:8]}",
                domain="Hardcoded Secrets & Poisoned AI Prompts",
                severity=sev,  # type: ignore[arg-type]
                source="gitleaks",
                title=f"Secret detected ({rule_id})",
                description=desc,
                file_path=_rel(item.get("File"), target_dir),
                line_number=item.get("StartLine"),
                snippet=f"Match: {secret}",
                remediation="Remove or rotate the exposed credential and verify it is not active.",
            )
        )

    return findings, f"ok ({len(findings)} findings)"


async def run_all_static_scanners(target_dir: Path, work_dir: Path) -> tuple[list[Finding], dict[str, str]]:
    """Run Semgrep, Trivy, and Gitleaks concurrently."""
    gitleaks_out = work_dir / "gitleaks_report.json"

    (sg_res, tr_res, gl_res) = await asyncio.gather(
        run_semgrep(target_dir),
        run_trivy(target_dir),
        run_gitleaks(target_dir, gitleaks_out),
    )

    all_findings = sg_res[0] + tr_res[0] + gl_res[0]
    statuses = {
        "semgrep": sg_res[1],
        "trivy": tr_res[1],
        "gitleaks": gl_res[1],
    }
    return all_findings, statuses
