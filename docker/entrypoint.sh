#!/usr/bin/env bash
set -euo pipefail

CODE_AUDIT_HOME="${CODE_AUDIT_HOME:-/opt/code-audit}"
TARGET_DIR="${TARGET_DIR:-/workspace}"
AUDIT_MODE="${AUDIT_MODE:-standard}"
AUDIT_OUTPUT="${AUDIT_OUTPUT:-/reports/audit-report.md}"
REPORT_LANG="${REPORT_LANG:-zh-CN}"
OPENCODE_AGENT="${OPENCODE_AGENT:-code-audit}"
OPENCODE_HOST="${OPENCODE_HOST:-0.0.0.0}"
OPENCODE_PORT="${OPENCODE_PORT:-4096}"

if [ "$(id -u)" = "0" ]; then
  mkdir -p \
    "${HOME}/.config/opencode" \
    "${HOME}/.local/share/opencode" \
    "${HOME}/.local/state/opencode" \
    "${HOME}/.cache/opencode" \
    "${HOME}/.opencode" \
    "$(dirname "${AUDIT_OUTPUT}")"
  chown -R node:node \
    "${HOME}/.config/opencode" \
    "${HOME}/.local" \
    "${HOME}/.cache" \
    "${HOME}/.opencode" \
    "$(dirname "${AUDIT_OUTPUT}")"
  exec gosu node /usr/local/bin/code-audit-entrypoint "$@"
fi

mkdir -p "$(dirname "${AUDIT_OUTPUT}")" "${HOME}/.opencode"
cd "${CODE_AUDIT_HOME}"

if [ "$#" -eq 0 ]; then
  set -- audit
fi

case "$1" in
  audit)
    shift
    if [ "$#" -gt 0 ]; then
      prompt="$*"
    else
      prompt="Run a ${AUDIT_MODE} security audit for target project: ${TARGET_DIR}. First explore the target project, then read ${TARGET_DIR}/audit-context.md if it exists and merge only code-backed context. Respond in ${REPORT_LANG}. Write the final report to ${AUDIT_OUTPUT}."
    fi
    exec opencode run --dir "${CODE_AUDIT_HOME}" --agent "${OPENCODE_AGENT}" "${prompt}"
    ;;
  tui)
    shift
    exec opencode "${CODE_AUDIT_HOME}" --agent "${OPENCODE_AGENT}" "$@"
    ;;
  serve)
    shift
    exec opencode serve --hostname "${OPENCODE_HOST}" --port "${OPENCODE_PORT}" "$@"
    ;;
  shell)
    shift
    exec "${SHELL:-/bin/bash}" "$@"
    ;;
  opencode)
    exec "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
