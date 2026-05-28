ARG NODE_VERSION=22-bookworm-slim

FROM node:${NODE_VERSION} AS runtime

ARG OPENCODE_VERSION=1.2.20
ARG INSTALL_SECURITY_TOOLS=false

ENV CODE_AUDIT_HOME=/opt/code-audit \
    TARGET_DIR=/workspace \
    AUDIT_MODE=standard \
    AUDIT_OUTPUT=/reports/audit-report.md \
    REPORT_LANG=zh-CN \
    HOME=/home/opencode \
    PATH=/opt/security-tools/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    NPM_CONFIG_UPDATE_NOTIFIER=false

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      fd-find \
      git \
      gosu \
      jq \
      less \
      openssh-client \
      python3 \
      python3-pip \
      python3-venv \
      ripgrep \
      tini \
      unzip \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g "opencode-ai@${OPENCODE_VERSION}"

RUN if [ "${INSTALL_SECURITY_TOOLS}" = "true" ]; then \
      python3 -m venv /opt/security-tools \
      && /opt/security-tools/bin/pip install --no-cache-dir --upgrade pip \
      && /opt/security-tools/bin/pip install --no-cache-dir bandit semgrep; \
    else \
      mkdir -p /opt/security-tools/bin; \
    fi

RUN mkdir -p /opt/code-audit /workspace /reports /home/opencode \
    && chown -R node:node /opt/code-audit /workspace /reports /home/opencode

WORKDIR /opt/code-audit

COPY --chown=node:node AGENTS.md opencode.json ./
COPY --chown=node:node references/ references/
COPY --chown=node:node .opencode/package.json .opencode/bun.lock .opencode/
COPY --chown=node:node .opencode/agents/ .opencode/agents/
COPY --chown=node:node .opencode/skills/ .opencode/skills/
COPY --chown=node:node .opencode/plugin/ .opencode/plugin/

RUN npm --prefix .opencode install --omit=dev \
    && chown -R node:node /opt/code-audit

COPY --chown=root:root docker/entrypoint.sh /usr/local/bin/code-audit-entrypoint
RUN chmod 0755 /usr/local/bin/code-audit-entrypoint

USER root

VOLUME ["/workspace", "/reports", "/home/opencode/.config/opencode", "/home/opencode/.local/share/opencode", "/home/opencode/.local/state/opencode", "/home/opencode/.cache/opencode", "/home/opencode/.opencode"]

ENTRYPOINT ["/usr/bin/tini", "--", "code-audit-entrypoint"]
CMD ["audit"]
