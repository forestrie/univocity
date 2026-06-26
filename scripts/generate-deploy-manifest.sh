#!/usr/bin/env bash
# Shell wrapper for generate-deploy-manifest.py (release CI).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_ID="${1:?release id required}"
python3 "${ROOT}/scripts/generate_deploy_manifest.py" "${RELEASE_ID}" "${@:2}"
