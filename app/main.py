"""Repo Gatekeeper FastAPI application and async audit pipeline."""

from __future__ import annotations

import asyncio
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .scanner.git_safe import safe_clone_and_inspect, validate_github_url
from .scanner.llm_reviewer import SEVERITY_RANK, check_llm_health, run_llm_review
from .scanner.manifest_audit import run_manifest_audit
from .scanner.models import ScanResult, ScanStage
from .scanner.report import build_domain_summaries, compute_verdict, export_clean_repo, render_markdown_report
from .scanner.static_tools import run_all_static_scanners

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
SCAN_ROOT = Path(os.getenv("GATEKEEPER_SCAN_DIR", "/tmp/gatekeeper_scans"))
APPROVED_ROOT = Path(os.getenv("GATEKEEPER_APPROVED_DIR", str(BASE_DIR / "approved_repos")))

DEFAULT_LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://host.docker.internal:11434/v1")
DEFAULT_LLM_MODEL = os.getenv("LLM_MODEL", "qwen2.5-coder:7b")
DEFAULT_LLM_API_KEY = os.getenv("LLM_API_KEY", "ollama")

app = FastAPI(title="Repo Gatekeeper", version="1.0.0")
if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

SCANS: dict[str, ScanResult] = {}


class CreateScanRequest(BaseModel):
    repo_url: str
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_api_key: str | None = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _init_stages() -> list[ScanStage]:
    return [
        ScanStage(key="clone", label="1. Safe Clone & Submodules"),
        ScanStage(key="static", label="2. Semgrep / Trivy / Gitleaks"),
        ScanStage(key="manifest", label="3. Manifest & Prompt Audit"),
        ScanStage(key="llm", label="4. Local LLM Review"),
        ScanStage(key="report", label="5. Final Report"),
    ]


def _set_stage(scan: ScanResult, key: str, status: str, detail: str | None = None) -> None:
    for st in scan.stages:
        if st.key == key:
            st.status = status  # type: ignore[assignment]
            if detail is not None:
                st.detail = detail
            break


async def _run_scan_pipeline(
    scan_id: str,
    repo_url: str,
    llm_base_url: str,
    llm_model: str,
    llm_api_key: str,
) -> None:
    scan = SCANS[scan_id]
    scan.status = "running"

    work_dir = SCAN_ROOT / scan_id
    repo_dir = work_dir / "repo"

    try:
        # Stage 1: Safe Clone & Submodules
        _set_stage(scan, "clone", "running", "Cloning with hooks disabled...")
        git_findings, git_meta = await safe_clone_and_inspect(repo_url, repo_dir)
        scan.findings.extend(git_findings)
        sub_note = "submodules checked" if git_meta.get("submodules_present") else "no submodules"
        _set_stage(scan, "clone", "completed", f"{len(git_findings)} findings ({sub_note})")

        # Stage 2: Deterministic Scanners
        _set_stage(scan, "static", "running", "Running Semgrep, Trivy, and Gitleaks...")
        static_findings, scanner_statuses = await run_all_static_scanners(repo_dir, work_dir)
        scan.findings.extend(static_findings)
        scan.scanner_versions = scanner_statuses
        _set_stage(scan, "static", "completed", f"{len(static_findings)} findings")

        # Stage 3: Manifest, AST & AI Prompt Audit
        _set_stage(scan, "manifest", "running", "Inspecting manifests, AST, containers & AI prompts...")
        manifest_findings = await asyncio.to_thread(run_manifest_audit, repo_dir)
        scan.findings.extend(manifest_findings)
        _set_stage(scan, "manifest", "completed", f"{len(manifest_findings)} findings")

        # Stage 4: Local LLM Adversarial Review
        _set_stage(scan, "llm", "running", f"Querying {llm_model}...")
        llm_findings, llm_status, llm_summary = await run_llm_review(
            repo_dir,
            scan.findings,
            base_url=llm_base_url,
            model=llm_model,
            api_key=llm_api_key,
        )
        scan.llm_status = llm_status
        scan.llm_summary = llm_summary
        scan.findings.extend(llm_findings)
        if llm_status == "connected":
            _set_stage(scan, "llm", "completed", f"{len(llm_findings)} findings")
        else:
            _set_stage(scan, "llm", "skipped", "LLM unreachable; deterministic scoring used")

        # Stage 5: Final 8-Domain Report
        _set_stage(scan, "report", "running", "Aggregating 8-domain report...")
        scan.findings.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 9))
        scan.domains = build_domain_summaries(scan.findings)
        scan.verdict = compute_verdict(scan.findings)
        scan.completed_at = _now_iso()
        scan.status = "completed"
        _set_stage(scan, "report", "completed", scan.verdict)

    except Exception as exc:
        scan.status = "failed"
        scan.error = str(exc)
        scan.completed_at = _now_iso()
        for st in scan.stages:
            if st.status == "running":
                st.status = "failed"
                st.detail = str(exc)[:180]


@app.get("/")
async def serve_index() -> FileResponse:
    index_path = STATIC_DIR / "index.html"
    if not index_path.is_file():
        raise HTTPException(status_code=404, detail="UI not found")
    return FileResponse(str(index_path))


@app.get("/api/config")
async def get_config(
    llm_base_url: str | None = Query(default=None),
    llm_api_key: str | None = Query(default=None),
    llm_model: str | None = Query(default=None),
) -> dict:
    base_url = (llm_base_url or DEFAULT_LLM_BASE_URL).strip()
    api_key = (llm_api_key if llm_api_key is not None else DEFAULT_LLM_API_KEY).strip()
    model = (llm_model or DEFAULT_LLM_MODEL).strip()
    health = await check_llm_health(base_url, api_key, model)
    return {
        "llm_base_url": base_url,
        "llm_model": model,
        "llm_connected": health["connected"],
        "llm_models": health["models"],
        "llm_error": health["error"],
    }


@app.post("/api/scans", status_code=202)
async def create_scan(req: CreateScanRequest) -> ScanResult:
    try:
        normalized_url, repo_name = validate_github_url(req.repo_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    scan_id = uuid.uuid4().hex[:12]
    scan = ScanResult(
        scan_id=scan_id,
        repo_url=normalized_url,
        repo_name=repo_name,
        status="queued",
        stages=_init_stages(),
        domains=build_domain_summaries([]),
        created_at=_now_iso(),
    )
    SCANS[scan_id] = scan

    base_url = (req.llm_base_url or DEFAULT_LLM_BASE_URL).strip()
    model = (req.llm_model or DEFAULT_LLM_MODEL).strip()
    api_key = (req.llm_api_key if req.llm_api_key is not None else DEFAULT_LLM_API_KEY).strip()

    asyncio.create_task(
        _run_scan_pipeline(scan_id, normalized_url, base_url, model, api_key)
    )
    return scan


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str) -> ScanResult:
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/api/scans/{scan_id}/report.md")
async def download_markdown(scan_id: str) -> PlainTextResponse:
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    md = render_markdown_report(scan)
    return PlainTextResponse(
        content=md,
        headers={"Content-Disposition": f'attachment; filename="gatekeeper-{scan.repo_name}.md"'},
    )


@app.get("/api/scans/{scan_id}/report.json")
async def download_json(scan_id: str) -> JSONResponse:
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(
        content=scan.model_dump(),
        headers={"Content-Disposition": f'attachment; filename="gatekeeper-{scan.repo_name}.json"'},
    )


@app.post("/api/scans/{scan_id}/export")
async def approve_and_export(scan_id: str) -> dict:
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="Scan must complete before exporting.")

    repo_dir = SCAN_ROOT / scan_id / "repo"
    try:
        dest = export_clean_repo(repo_dir, APPROVED_ROOT, scan.repo_name)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    scan.exported_path = str(dest)
    return {"status": "exported", "exported_path": str(dest), "repo_name": scan.repo_name}


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str) -> dict:
    scan = SCANS.pop(scan_id, None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    work_dir = SCAN_ROOT / scan_id
    if work_dir.exists():
        shutil.rmtree(work_dir, ignore_errors=True)
    return {"status": "deleted"}
