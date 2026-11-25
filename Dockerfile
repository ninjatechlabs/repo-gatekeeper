FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SEMGREP_SEND_METRICS=off \
    PIP_DISABLE_PIP_VERSION_CHECK=1

ARG TRIVY_VERSION=0.76.2
ARG GITLEAKS_VERSION=8.30.1

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    tar \
    gzip \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy binary
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
        amd64) TRIVY_ARCH="64bit" ;; \
        arm64) TRIVY_ARCH="ARM64" ;; \
        *) echo "Unsupported architecture: $ARCH" && exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin trivy && \
    chmod +x /usr/local/bin/trivy

# Install Gitleaks binary
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
        amd64) GITLEAKS_ARCH="x64" ;; \
        arm64) GITLEAKS_ARCH="arm64" ;; \
        *) echo "Unsupported architecture: $ARCH" && exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks

# Install Semgrep CE in an isolated venv to avoid dependency conflicts with FastAPI
RUN python -m venv /opt/semgrep-venv && \
    /opt/semgrep-venv/bin/pip install --no-cache-dir semgrep && \
    ln -s /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY static/ ./static/

RUN mkdir -p /tmp/gatekeeper_scans /app/approved_repos && \
    groupadd -r gatekeeper && useradd -r -g gatekeeper -m -d /home/gatekeeper gatekeeper && \
    chown -R gatekeeper:gatekeeper /app /tmp/gatekeeper_scans /home/gatekeeper

# Verify all scanner binaries are available
RUN git --version && semgrep --version && trivy --version && gitleaks version

USER gatekeeper

EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8088/api/config || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8088"]
