#!/usr/bin/env bash
# Install SkillSpector into its own venv for sentinel-scan to invoke.
#
#   venv: ~/.local/share/tav.sentinel/scanner
#   tag:  v2.9.6 (pinned; matches .skillspector-baseline.yaml's scanner_version)
#
# Never runs automatically -- no code path in src/sentinel/ invokes this
# script. Requires an explicit --yes; without it, prints what it would do
# and exits 0 without touching the filesystem. Runs entirely as the calling
# user and never writes outside the user's own HOME.
set -euo pipefail

VENV_DIR="$HOME/.local/share/tav.sentinel/scanner"
PACKAGE="git+https://github.com/NVIDIA/skillspector.git@v2.9.6"

usage() {
  echo "Usage: $0 --yes"
  echo
  echo "This will:"
  echo "  1. create a Python venv at: $VENV_DIR"
  echo "  2. pip install (network required): $PACKAGE"
  echo
  echo "Re-run with --yes to actually do this."
}

if [[ "${1:-}" != "--yes" ]]; then
  usage
  exit 0
fi

echo "Creating venv at $VENV_DIR ..."
python3 -m venv "$VENV_DIR"

echo "Installing $PACKAGE ..."
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install "$PACKAGE"

echo "Installed. Binary at: $VENV_DIR/bin/skillspector"
"$VENV_DIR/bin/skillspector" --version || true
