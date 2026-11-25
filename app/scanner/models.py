"""Shared data models and domain constants for Repo Gatekeeper."""

from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field

DOMAINS: list[str] = [
    "Install-Time & Build-Time Hooks",
    "Malicious Payloads & Obfuscation",
    "Data Exfiltration & Network Activity",
    "Supply Chain, Dependencies & Submodules",
    "File System & Privilege Escalation",
    "Container & Sandbox Escape Risks",
    "Application & Runtime Vulnerabilities",
    "Hardcoded Secrets & Poisoned AI Prompts",
]

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
DomainStatus = Literal["PASS", "WARN", "FAIL"]
Verdict = Literal["SAFE TO INSTALL", "SAFE WITH MODIFICATIONS", "DO NOT INSTALL"]


class Finding(BaseModel):
    id: str
    domain: str
    severity: Severity
    source: str
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    snippet: Optional[str] = None
    remediation: str = "Review the flagged code or configuration before installing."


class DomainSummary(BaseModel):
    domain: str
    status: DomainStatus
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanStage(BaseModel):
    key: str
    label: str
    status: Literal["pending", "running", "completed", "failed", "skipped"] = "pending"
    detail: Optional[str] = None


class ScanResult(BaseModel):
    scan_id: str
    repo_url: str
    repo_name: str
    status: Literal["queued", "running", "completed", "failed"] = "queued"
    verdict: Optional[Verdict] = None
    stages: list[ScanStage] = Field(default_factory=list)
    domains: list[DomainSummary] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    llm_status: str = "pending"
    llm_summary: Optional[str] = None
    scanner_versions: dict[str, str] = Field(default_factory=dict)
    error: Optional[str] = None
    created_at: str
    completed_at: Optional[str] = None
    exported_path: Optional[str] = None
