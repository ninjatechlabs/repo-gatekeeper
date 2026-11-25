# Repo Gatekeeper

Zero-trust pre-installation security auditor for public GitHub repositories. Evaluates repositories in an isolated container using deterministic static scanners, custom AST/manifest/prompt-injection checks, and an optional local OpenAI-compatible LLM before you clone or run anything on your machine.

## Features

1. **Zero-Trust Git Clone & Submodule Inspection (`app/scanner/git_safe.py`)**
   - Strictly validates `https://github.com/<owner>/<repo>` URLs (blocks `file://`, `ssh://`, `git://`, shell metacharacters, and path traversal).
   - Clones with `core.hooksPath=/dev/null` and `--no-recurse-submodules`.
   - Audits `.git/hooks/`, `.git/config`, and `.gitmodules` before safely initializing valid HTTPS submodules.
2. **Deterministic Security Scanners (`app/scanner/static_tools.py`)**
   - **Semgrep CE** (`semgrep scan --config auto --json`, telemetry disabled)
   - **Trivy** (`trivy fs --scanners vuln,misconfig --include-dev-deps --format json`)
   - **Gitleaks** (`gitleaks dir --no-banner --report-format json`)
3. **Custom Python AST, Manifest & AI Prompt Inspector (`app/scanner/manifest_audit.py`)**
   - Checks `package.json` lifecycle hooks (`preinstall`, `install`, `postinstall`, `prepare`), `setup.py` AST & `cmdclass`, `pyproject.toml` `backend-path`.
   - Checks `.vscode/tasks.json` (`runOn: folderOpen`) and `.devcontainer/devcontainer.json`.
   - Flags obfuscated/dropper patterns (`curl | sh`, `wget -O- | bash`, `base64 -d`, `powershell -enc`, `eval()`, `exec()`, `subprocess(..., shell=True)`), `0.0.0.0` bindings, committed binaries (`.exe`, `.dll`, `.so`, `.bin`, `.whl`), container escapes (`privileged`, `docker.sock`, `network_mode: host`), and poisoned AI instruction files (`AGENTS.md`, `.cursorrules`, `CLAUDE.md`, `copilot-instructions.md`, `mcp.json`).
4. **Local LLM Adversarial Review (`app/scanner/llm_reviewer.py`)**
   - Connects to Ollama (`http://host.docker.internal:11434/v1`) or OmniRoute (`http://host.docker.internal:20128/v1`), or falls back gracefully to deterministic-only scoring if unreachable.
5. **8-Domain Aggregator & Safe Export Gate (`app/scanner/report.py`)**
   - Produces `SAFE TO INSTALL`, `SAFE WITH MODIFICATIONS`, or `DO NOT INSTALL`.
   - Exports a clean copy (with `.git` stripped) to `./approved_repos/<owner>__<repo>` only on explicit approval.

## Quick Start (Windows 11 / WSL Ubuntu)

1. Open your **WSL Ubuntu** terminal and navigate to the project directory:
   ```bash
   cd ~/repo-gatekeeper
   cp .env.example .env
   ```

2. *(Optional)* Edit `.env` if you use OmniRoute (`http://host.docker.internal:20128/v1`) or a different model than `qwen2.5-coder:7b`.

3. Build and start the container:
   ```bash
   docker compose up --build
   ```

4. Open the dashboard in your browser:
   - `http://localhost:8088`

## Safe Verification Test

Once the container is running on port `8088`, you can test the full pipeline against a benign public repository (`https://github.com/octocat/Hello-World`) via `curl`:

```bash
curl -s -X POST http://localhost:8088/api/scans \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/octocat/Hello-World"}' | jq .
```

Or paste `https://github.com/octocat/Hello-World` into the web UI at `http://localhost:8088` and click **Run Security Audit**.
