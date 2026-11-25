"""Custom Python AST, manifest, container, binary, and AI prompt-injection inspector."""

from __future__ import annotations

import ast
import json
import re
import tomllib
import uuid
from pathlib import Path

from .models import Finding

NPM_LIFECYCLE_HOOKS = (
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishonly",
    "postuninstall",
)

DANGEROUS_SCRIPT_PATTERNS: list[tuple[re.Pattern[str], str, str, str]] = [
    (
        re.compile(r"curl\s+[^|\n]*\|\s*(?:ba)?sh", re.IGNORECASE),
        "CRITICAL",
        "Remote script piped directly to shell (curl | sh)",
        "Malicious Payloads & Obfuscation",
    ),
    (
        re.compile(r"wget\s+[^|\n]*-O\s*-\s*\|\s*(?:ba)?sh", re.IGNORECASE),
        "CRITICAL",
        "Remote script piped directly to shell (wget -O- | bash)",
        "Malicious Payloads & Obfuscation",
    ),
    (
        re.compile(r"base64\s+(?:-d|--decode)", re.IGNORECASE),
        "HIGH",
        "Base64 decoding in script/build file",
        "Malicious Payloads & Obfuscation",
    ),
    (
        re.compile(r"powershell(?:\.exe)?\s+[^\n]*-(?:e|enc|encodedcommand)\b", re.IGNORECASE),
        "CRITICAL",
        "Encoded PowerShell execution",
        "Malicious Payloads & Obfuscation",
    ),
    (
        re.compile(r"\b(?:eval|exec)\s*\("),
        "HIGH",
        "Dynamic eval()/exec() invocation",
        "Malicious Payloads & Obfuscation",
    ),
]

BINARY_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".bin", ".whl", ".msi", ".elf", ".apk"}

AI_CONFIG_FILENAMES = {
    "agents.md",
    ".cursorrules",
    "claude.md",
    "gemini.md",
    ".windsurfrules",
    "copilot-instructions.md",
    "mcp.json",
    ".mcp.json",
}

PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.IGNORECASE), "Instruction override phrase"),
    (re.compile(r"(?:disregard|forget)\s+(?:all\s+)?(?:previous|system)\s+(?:rules|instructions|prompt)", re.IGNORECASE), "System prompt override attempt"),
    (re.compile(r"(?:do\s+not|don't|never)\s+(?:tell|inform|show|mention\s+to)\s+the\s+user", re.IGNORECASE), "Concealment instruction"),
    (re.compile(r"(?:silently|secretly|quietly)\s+(?:run|execute|send|upload|exfiltrate|curl|post)", re.IGNORECASE), "Covert execution instruction"),
    (re.compile(r"<!--[\s\S]*?(?:ignore|curl|wget|ssh|exfiltrate|execute|powershell|bash)[\s\S]*?-->", re.IGNORECASE), "Suspicious hidden HTML comment"),
]

INVISIBLE_UNICODE_RE = re.compile(r"[\u200b\u200c\u200d\ufeff\u202a-\u202e\u2060-\u2064]")
SENSITIVE_PATHS_RE = re.compile(r"(?:~|/home/[^/]+|%USERPROFILE%)/(?:\.ssh|\.aws|\.gnupg|\.kube)|/etc/passwd|/etc/shadow")
OUTBOUND_HTTP_CALL_PREFIXES = ("requests.", "urllib.request.", "httpx.", "aiohttp.", "http.client.")
BIND_ALL_INTERFACES_RE = re.compile(r"""(?:host\s*=\s*['"]0\.0\.0\.0['"]|--host(?:=|\s+)0\.0\.0\.0|bind\s*[:=]\s*['"]0\.0\.0\.0)""")


def _rel(path: Path, root: Path) -> str:
    return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")


def _strip_jsonc_comments(text: str) -> str:
    text = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)
    text = re.sub(r"/\*[\s\S]*?\*/", "", text)
    return text


def _inspect_package_json(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return findings

    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for hook_name, cmd in scripts.items():
            if hook_name.lower() in NPM_LIFECYCLE_HOOKS and isinstance(cmd, str):
                is_crit = any(k in cmd.lower() for k in ("curl", "wget", "bash", "sh -c", "powershell", "base64", "eval", "node -e"))
                findings.append(
                    Finding(
                        id=f"npm-hook-{uuid.uuid4().hex[:8]}",
                        domain="Install-Time & Build-Time Hooks",
                        severity="CRITICAL" if is_crit else "HIGH",
                        source="manifest_audit",
                        title=f"npm lifecycle hook '{hook_name}' in package.json",
                        description=f"Script '{hook_name}' executes automatically during npm install: {cmd[:200]}",
                        file_path=_rel(path, root),
                        snippet=f'"{hook_name}": "{cmd[:200]}"',
                        remediation="Inspect this lifecycle script or run npm install with --ignore-scripts.",
                    )
                )
    return findings


def _inspect_setup_py(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    rel_path = _rel(path, root)

    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = ""
            if isinstance(node.func, ast.Name):
                call_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                parts = []
                cur: ast.AST = node.func
                while isinstance(cur, ast.Attribute):
                    parts.append(cur.attr)
                    cur = cur.value
                if isinstance(cur, ast.Name):
                    parts.append(cur.id)
                call_name = ".".join(reversed(parts))

            if call_name in ("os.system", "os.popen", "eval", "exec", "compile", "__import__") or call_name.startswith(
                ("subprocess.", "ctypes.", "urllib.request.", "requests.", "httpx.", "socket.")
            ):
                findings.append(
                    Finding(
                        id=f"setup-exec-{uuid.uuid4().hex[:8]}",
                        domain="Install-Time & Build-Time Hooks",
                        severity="CRITICAL",
                        source="manifest_audit",
                        title=f"Code/network execution in setup.py ({call_name})",
                        description=f"setup.py invokes '{call_name}', which runs during pip install.",
                        file_path=rel_path,
                        line_number=getattr(node, "lineno", None),
                        remediation="Avoid installing packages with arbitrary execution in setup.py; inspect thoroughly.",
                    )
                )

            if call_name.endswith("setup"):
                for kw in node.keywords:
                    if kw.arg == "cmdclass":
                        findings.append(
                            Finding(
                                id=f"setup-cmdclass-{uuid.uuid4().hex[:8]}",
                                domain="Install-Time & Build-Time Hooks",
                                severity="HIGH",
                                source="manifest_audit",
                                title="Custom cmdclass in setup.py",
                                description="setup.py defines a custom cmdclass, which can override install/build commands.",
                                file_path=rel_path,
                                line_number=getattr(kw, "lineno", None),
                                remediation="Inspect the custom cmdclass implementation before running pip install.",
                            )
                        )
    return findings


def _inspect_pyproject(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return findings

    build_sys = data.get("build-system", {})
    if isinstance(build_sys, dict):
        if "backend-path" in build_sys:
            findings.append(
                Finding(
                    id=f"pyproj-backend-{uuid.uuid4().hex[:8]}",
                    domain="Install-Time & Build-Time Hooks",
                    severity="HIGH",
                    source="manifest_audit",
                    title="Custom local build-system backend-path in pyproject.toml",
                    description="pyproject.toml specifies a local 'backend-path' that executes custom build code on pip install.",
                    file_path=_rel(path, root),
                    snippet=str(build_sys)[:200],
                    remediation="Audit the local build backend code before building or installing.",
                )
            )
    return findings


def _inspect_vscode_and_devcontainer(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    rel_path = _rel(path, root)
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(_strip_jsonc_comments(raw))
    except Exception:
        return findings

    if path.name == "tasks.json":
        for task in data.get("tasks", []) or []:
            if isinstance(task, dict):
                run_opts = task.get("runOptions", {})
                if isinstance(run_opts, dict) and run_opts.get("runOn") == "folderOpen":
                    findings.append(
                        Finding(
                            id=f"vscode-auto-{uuid.uuid4().hex[:8]}",
                            domain="Install-Time & Build-Time Hooks",
                            severity="CRITICAL",
                            source="manifest_audit",
                            title="VS Code task auto-executes on folderOpen",
                            description=f"Task '{task.get('label', 'unnamed')}' has runOn: folderOpen and runs automatically when opened in VS Code.",
                            file_path=rel_path,
                            snippet=str(task.get("command", ""))[:200],
                            remediation="Remove 'runOn: folderOpen' or disable automatic tasks in VS Code.",
                        )
                    )

    if path.name == "devcontainer.json":
        for hook in ("initializeCommand", "onCreateCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"):
            if hook in data:
                findings.append(
                    Finding(
                        id=f"devc-hook-{uuid.uuid4().hex[:8]}",
                        domain="Install-Time & Build-Time Hooks",
                        severity="MEDIUM",
                        source="manifest_audit",
                        title=f"Devcontainer lifecycle hook '{hook}'",
                        description=f"devcontainer.json defines '{hook}': {str(data[hook])[:180]}",
                        file_path=rel_path,
                        remediation="Verify the devcontainer command before opening in a container.",
                    )
                )
        if data.get("privileged") is True or "--privileged" in str(data.get("runArgs", "")):
            findings.append(
                Finding(
                    id=f"devc-priv-{uuid.uuid4().hex[:8]}",
                    domain="Container & Sandbox Escape Risks",
                    severity="CRITICAL",
                    source="manifest_audit",
                    title="Privileged devcontainer configuration",
                    description="devcontainer.json requests privileged container execution.",
                    file_path=rel_path,
                    remediation="Remove privileged mode from devcontainer.json.",
                )
            )
    return findings


def _inspect_python_file(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    rel_path = _rel(path, root)
    text = path.read_text(encoding="utf-8", errors="replace")

    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        tree = None

    has_outbound_http = False
    has_sensitive_path_literal = False

    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                # Ignore long prompt/documentation strings and regex-like patterns
                if len(node.value) <= 200 and "(?:" not in node.value and SENSITIVE_PATHS_RE.search(node.value):
                    has_sensitive_path_literal = True

            if isinstance(node, ast.Call):
                call_name = ""
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    parts = []
                    cur: ast.AST = node.func
                    while isinstance(cur, ast.Attribute):
                        parts.append(cur.attr)
                        cur = cur.value
                    if isinstance(cur, ast.Name):
                        parts.append(cur.id)
                    call_name = ".".join(reversed(parts))

                if call_name.startswith(OUTBOUND_HTTP_CALL_PREFIXES):
                    has_outbound_http = True

                if call_name in ("eval", "exec"):
                    findings.append(
                        Finding(
                            id=f"py-eval-{uuid.uuid4().hex[:8]}",
                            domain="Malicious Payloads & Obfuscation",
                            severity="MEDIUM",
                            source="manifest_audit",
                            title=f"Dynamic {call_name}() call in Python",
                            description=f"Python code calls {call_name}(), which can execute dynamically constructed code.",
                            file_path=rel_path,
                            line_number=getattr(node, "lineno", None),
                            remediation="Ensure inputs to eval/exec are strictly trusted or replace with safe parsing.",
                        )
                    )
                elif call_name in ("os.system", "os.popen") or call_name.startswith("ctypes."):
                    findings.append(
                        Finding(
                            id=f"py-sys-{uuid.uuid4().hex[:8]}",
                            domain="File System & Privilege Escalation",
                            severity="MEDIUM",
                            source="manifest_audit",
                            title=f"System/native call ({call_name})",
                            description=f"Code invokes {call_name}, allowing shell or native memory execution.",
                            file_path=rel_path,
                            line_number=getattr(node, "lineno", None),
                            remediation="Verify the arguments are static and non-malicious.",
                        )
                    )
                elif call_name.startswith("subprocess."):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append(
                                Finding(
                                    id=f"py-subshell-{uuid.uuid4().hex[:8]}",
                                    domain="Application & Runtime Vulnerabilities",
                                    severity="HIGH",
                                    source="manifest_audit",
                                    title=f"{call_name}(shell=True) usage",
                                    description="Subprocess invoked with shell=True, risking command injection.",
                                    file_path=rel_path,
                                    line_number=getattr(node, "lineno", None),
                                    remediation="Use argument lists with shell=False.",
                                )
                            )

    if has_sensitive_path_literal and has_outbound_http:
        findings.append(
            Finding(
                id=f"py-exfil-{uuid.uuid4().hex[:8]}",
                domain="Data Exfiltration & Network Activity",
                severity="CRITICAL",
                source="manifest_audit",
                title="Potential credential/sensitive-path exfiltration",
                description="File references sensitive paths (~/.ssh, ~/.aws, /etc/passwd) alongside outbound HTTP/network calls.",
                file_path=rel_path,
                remediation="Inspect this file immediately for data exfiltration behavior.",
            )
        )

    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#") or "re.compile" in stripped:
            continue
        if BIND_ALL_INTERFACES_RE.search(stripped):
            findings.append(
                Finding(
                    id=f"net-bind-{uuid.uuid4().hex[:8]}",
                    domain="Application & Runtime Vulnerabilities",
                    severity="LOW",
                    source="manifest_audit",
                    title="Server binds to all interfaces (0.0.0.0)",
                    description="Service binds to 0.0.0.0, exposing it on all network interfaces.",
                    file_path=rel_path,
                    line_number=lineno,
                    snippet=stripped[:200],
                    remediation="Bind to 127.0.0.1 for local-only use or ensure authentication is enabled.",
                )
            )

    return findings


def _inspect_container_file(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    rel_path = _rel(path, root)
    text = path.read_text(encoding="utf-8", errors="replace")

    for lineno, line in enumerate(text.splitlines(), start=1):
        low = line.lower()
        if "privileged: true" in low or "--privileged" in low:
            findings.append(
                Finding(
                    id=f"ctr-priv-{uuid.uuid4().hex[:8]}",
                    domain="Container & Sandbox Escape Risks",
                    severity="CRITICAL",
                    source="manifest_audit",
                    title="Privileged container mode enabled",
                    description="Container runs in privileged mode, granting near-root host access.",
                    file_path=rel_path,
                    line_number=lineno,
                    snippet=line.strip()[:200],
                    remediation="Remove privileged: true / --privileged.",
                )
            )
        if "docker.sock" in low:
            findings.append(
                Finding(
                    id=f"ctr-sock-{uuid.uuid4().hex[:8]}",
                    domain="Container & Sandbox Escape Risks",
                    severity="CRITICAL",
                    source="manifest_audit",
                    title="Docker socket mounted inside container",
                    description="Mounting /var/run/docker.sock allows full host takeover from inside the container.",
                    file_path=rel_path,
                    line_number=lineno,
                    snippet=line.strip()[:200],
                    remediation="Remove the docker.sock mount.",
                )
            )
        if "network_mode: host" in low or "--net=host" in low or "--network=host" in low:
            findings.append(
                Finding(
                    id=f"ctr-net-{uuid.uuid4().hex[:8]}",
                    domain="Container & Sandbox Escape Risks",
                    severity="HIGH",
                    source="manifest_audit",
                    title="Host network mode enabled",
                    description="Container shares the host network namespace.",
                    file_path=rel_path,
                    line_number=lineno,
                    snippet=line.strip()[:200],
                    remediation="Use bridge networking instead of host network mode.",
                )
            )
    return findings


def _inspect_ai_prompt_file(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    rel_path = _rel(path, root)
    text = path.read_text(encoding="utf-8", errors="replace")

    if INVISIBLE_UNICODE_RE.search(text):
        findings.append(
            Finding(
                id=f"ai-unicode-{uuid.uuid4().hex[:8]}",
                domain="Hardcoded Secrets & Poisoned AI Prompts",
                severity="HIGH",
                source="manifest_audit",
                title="Hidden/invisible Unicode characters in AI config file",
                description="File contains zero-width or bidirectional override Unicode characters, often used to hide prompt injections.",
                file_path=rel_path,
                remediation="Inspect the file with a hex/Unicode viewer and strip hidden characters.",
            )
        )

    for pattern, label in PROMPT_INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            findings.append(
                Finding(
                    id=f"ai-inject-{uuid.uuid4().hex[:8]}",
                    domain="Hardcoded Secrets & Poisoned AI Prompts",
                    severity="CRITICAL",
                    source="manifest_audit",
                    title=f"Prompt injection pattern: {label}",
                    description=f"AI configuration file contains suspicious instruction pattern: '{m.group(0)[:120]}'",
                    file_path=rel_path,
                    snippet=m.group(0)[:200],
                    remediation="Remove or sanitize the poisoned AI instruction file before opening in an AI IDE.",
                )
            )
    return findings


def run_manifest_audit(target_dir: Path) -> list[Finding]:
    """Walk target_dir and run custom AST, manifest, script, binary, and AI prompt checks."""
    findings: list[Finding] = []

    for path in target_dir.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue

        name_low = path.name.lower()
        suffix_low = path.suffix.lower()
        rel_path = _rel(path, target_dir)

        # 1. Compiled binaries / executables
        if suffix_low in BINARY_EXTENSIONS:
            domain = "Supply Chain, Dependencies & Submodules" if suffix_low == ".whl" else "Malicious Payloads & Obfuscation"
            findings.append(
                Finding(
                    id=f"bin-{uuid.uuid4().hex[:8]}",
                    domain=domain,
                    severity="HIGH",
                    source="manifest_audit",
                    title=f"Pre-compiled binary/archive committed: {path.name}",
                    description=f"Repository contains compiled binary or wheel '{rel_path}' which cannot be audited as plain text.",
                    file_path=rel_path,
                    remediation="Verify the binary's provenance or remove it and build from source.",
                )
            )
            continue

        # Skip very large files (> 2 MB) for text scanning
        try:
            if path.stat().st_size > 2 * 1024 * 1024:
                continue
        except OSError:
            continue

        # 2. Package & build manifests
        if name_low == "package.json":
            findings.extend(_inspect_package_json(path, target_dir))
        elif name_low == "setup.py":
            findings.extend(_inspect_setup_py(path, target_dir))
        elif name_low == "pyproject.toml":
            findings.extend(_inspect_pyproject(path, target_dir))
        elif rel_path.lower() in (".vscode/tasks.json", ".devcontainer/devcontainer.json"):
            findings.extend(_inspect_vscode_and_devcontainer(path, target_dir))

        # 3. Container configs
        if "dockerfile" in name_low or re.match(r"^(?:docker-)?compose.*\.ya?ml$", name_low):
            findings.extend(_inspect_container_file(path, target_dir))

        # 4. AI / Agent configs
        if name_low in AI_CONFIG_FILENAMES or ".cursor/mcp.json" in rel_path.lower():
            findings.extend(_inspect_ai_prompt_file(path, target_dir))

        # 5. Python AST inspection
        if suffix_low == ".py":
            findings.extend(_inspect_python_file(path, target_dir))

        # 6. Shell / script / Makefile / Dockerfile payload patterns
        if suffix_low in (".sh", ".ps1", ".bat", ".cmd") or name_low == "makefile" or "dockerfile" in name_low:
            text = path.read_text(encoding="utf-8", errors="replace")
            for lineno, line in enumerate(text.splitlines(), start=1):
                for pat, sev, title, domain in DANGEROUS_SCRIPT_PATTERNS:
                    if pat.search(line):
                        findings.append(
                            Finding(
                                id=f"script-{uuid.uuid4().hex[:8]}",
                                domain=domain,
                                severity=sev,  # type: ignore[arg-type]
                                source="manifest_audit",
                                title=title,
                                description=f"Potentially dangerous command pattern in {path.name}.",
                                file_path=rel_path,
                                line_number=lineno,
                                snippet=line.strip()[:200],
                                remediation="Inspect the script line carefully before executing.",
                            )
                        )

    return findings
