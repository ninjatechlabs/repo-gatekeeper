"""Zero-trust Git clone and submodule inspection."""

from __future__ import annotations

import asyncio
import configparser
import os
import re
import uuid
from pathlib import Path
from typing import Tuple

from .models import Finding

GITHUB_URL_RE = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
SHELL_META_RE = re.compile(r"[;&|`$<>()\{\}\[\]\\\n\r]")

SUSPICIOUS_GIT_CONFIG_KEYS = (
    "hookspath",
    "fsmonitor",
    "sshcommand",
    "uploadpack",
    "receivepack",
    "credential.helper",
    "insteadof",
    "smudge",
    "clean",
)


def validate_github_url(url: str) -> Tuple[str, str]:
    """Validate that url is a public https://github.com/owner/repo URL.

    Returns (normalized_url, repo_name) or raises ValueError.
    """
    cleaned = (url or "").strip()
    if not cleaned:
        raise ValueError("Repository URL cannot be empty.")

    if SHELL_META_RE.search(cleaned):
        raise ValueError("Repository URL contains forbidden characters.")

    lowered = cleaned.lower()
    if lowered.startswith(("file://", "ssh://", "git://", "http://")):
        raise ValueError("Only public https://github.com/ URLs are permitted.")

    match = GITHUB_URL_RE.match(cleaned)
    if not match:
        raise ValueError(
            "Invalid GitHub URL. Expected format: https://github.com/<owner>/<repo>"
        )

    owner, repo = match.group(1), match.group(2)
    if owner in (".", "..") or repo in (".", "..") or ".." in owner or ".." in repo:
        raise ValueError("Repository URL contains invalid path segments.")

    normalized = f"https://github.com/{owner}/{repo}"
    return normalized, f"{owner}__{repo}"


async def _run_git(args: list[str], cwd: Path | None = None, timeout: int = 120) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ALLOW_PROTOCOL"] = "https"

    proc = await asyncio.create_subprocess_exec(
        "git",
        *args,
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
        return -1, "", f"git command timed out after {timeout}s"

    return (
        proc.returncode or 0,
        stdout_b.decode("utf-8", errors="replace"),
        stderr_b.decode("utf-8", errors="replace"),
    )


async def safe_clone_and_inspect(url: str, target_dir: Path) -> tuple[list[Finding], dict]:
    """Clone a GitHub repository with hooks disabled and inspect git metadata & submodules."""
    findings: list[Finding] = []
    meta: dict = {"submodules_present": False, "submodules_initialized": False}

    normalized_url, _ = validate_github_url(url)
    target_dir.parent.mkdir(parents=True, exist_ok=True)

    rc, _, err = await _run_git(
        [
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.file.allow=never",
            "clone",
            "--depth",
            "1",
            "--no-recurse-submodules",
            normalized_url,
            str(target_dir),
        ],
        timeout=180,
    )
    if rc != 0:
        raise RuntimeError(f"Git clone failed: {err.strip() or 'Unknown git error'}")

    # 1. Inspect .git/hooks/
    hooks_dir = target_dir / ".git" / "hooks"
    if hooks_dir.is_dir():
        for item in hooks_dir.iterdir():
            if item.is_file() and not item.name.endswith(".sample"):
                findings.append(
                    Finding(
                        id=f"git-hook-{uuid.uuid4().hex[:8]}",
                        domain="Install-Time & Build-Time Hooks",
                        severity="CRITICAL",
                        source="git_safe",
                        title=f"Non-sample git hook present: {item.name}",
                        description="Unexpected executable or script found inside .git/hooks/.",
                        file_path=f".git/hooks/{item.name}",
                        remediation="Remove .git directory before using this repository.",
                    )
                )

    # 2. Inspect .git/config
    git_config = target_dir / ".git" / "config"
    if git_config.is_file():
        config_text = git_config.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(config_text.splitlines(), start=1):
            low = line.lower().strip()
            if any(key in low for key in SUSPICIOUS_GIT_CONFIG_KEYS):
                findings.append(
                    Finding(
                        id=f"git-cfg-{uuid.uuid4().hex[:8]}",
                        domain="Supply Chain, Dependencies & Submodules",
                        severity="HIGH",
                        source="git_safe",
                        title="Suspicious .git/config directive",
                        description=f"Potentially dangerous git configuration directive found: {line.strip()}",
                        file_path=".git/config",
                        line_number=lineno,
                        snippet=line.strip()[:200],
                        remediation="Strip .git before using the repository and verify config directives.",
                    )
                )

    # 3. Inspect .gitmodules
    gitmodules_path = target_dir / ".gitmodules"
    if gitmodules_path.is_file():
        meta["submodules_present"] = True
        submodules_safe = True
        gm_text = gitmodules_path.read_text(encoding="utf-8", errors="replace")

        parser = configparser.ConfigParser()
        try:
            parser.read_string(gm_text)
        except configparser.Error as exc:
            submodules_safe = False
            findings.append(
                Finding(
                    id=f"gitmod-parse-{uuid.uuid4().hex[:8]}",
                    domain="Supply Chain, Dependencies & Submodules",
                    severity="HIGH",
                    source="git_safe",
                    title="Malformed .gitmodules file",
                    description=f"Could not parse .gitmodules safely: {exc}",
                    file_path=".gitmodules",
                    remediation="Inspect .gitmodules manually before initializing submodules.",
                )
            )

        for section in parser.sections():
            sub_url = parser.get(section, "url", fallback="").strip()
            sub_path = parser.get(section, "path", fallback="").strip()
            sub_update = parser.get(section, "update", fallback="").strip()

            if not sub_url.startswith("https://"):
                submodules_safe = False
                findings.append(
                    Finding(
                        id=f"gitmod-url-{uuid.uuid4().hex[:8]}",
                        domain="Supply Chain, Dependencies & Submodules",
                        severity="HIGH",
                        source="git_safe",
                        title=f"Non-HTTPS submodule URL in {section}",
                        description=f"Submodule '{section}' uses non-HTTPS URL '{sub_url}'.",
                        file_path=".gitmodules",
                        snippet=f"url = {sub_url}",
                        remediation="Only allow HTTPS submodule URLs from trusted origins.",
                    )
                )

            if ".." in sub_url or ".." in sub_path or SHELL_META_RE.search(sub_url):
                submodules_safe = False
                findings.append(
                    Finding(
                        id=f"gitmod-trav-{uuid.uuid4().hex[:8]}",
                        domain="Supply Chain, Dependencies & Submodules",
                        severity="CRITICAL",
                        source="git_safe",
                        title=f"Path traversal or unsafe characters in submodule {section}",
                        description=f"Submodule '{section}' contains relative '../' traversal or shell metacharacters.",
                        file_path=".gitmodules",
                        snippet=f"path = {sub_path} | url = {sub_url}",
                        remediation="Do not initialize this submodule; it may attempt arbitrary file write or command injection.",
                    )
                )

            if sub_update and sub_update.lower() not in ("checkout", "rebase", "merge", "none"):
                submodules_safe = False
                findings.append(
                    Finding(
                        id=f"gitmod-upd-{uuid.uuid4().hex[:8]}",
                        domain="Install-Time & Build-Time Hooks",
                        severity="CRITICAL",
                        source="git_safe",
                        title=f"Custom submodule update command in {section}",
                        description=f"Submodule '{section}' defines custom update directive '{sub_update}'.",
                        file_path=".gitmodules",
                        snippet=f"update = {sub_update}",
                        remediation="Remove custom submodule update commands; they can execute arbitrary shell code.",
                    )
                )

        if submodules_safe:
            rc_sub, _, err_sub = await _run_git(
                [
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "protocol.file.allow=never",
                    "submodule",
                    "update",
                    "--init",
                    "--recursive",
                    "--depth",
                    "1",
                ],
                cwd=target_dir,
                timeout=180,
            )
            if rc_sub != 0:
                findings.append(
                    Finding(
                        id=f"gitmod-init-{uuid.uuid4().hex[:8]}",
                        domain="Supply Chain, Dependencies & Submodules",
                        severity="HIGH",
                        source="git_safe",
                        title="Submodule initialization failed or unreachable",
                        description=f"Failed to safely fetch submodules: {err_sub.strip()[:300]}",
                        file_path=".gitmodules",
                        remediation="Verify all submodule repositories are reachable and benign.",
                    )
                )
            else:
                meta["submodules_initialized"] = True

    return findings, meta
