#!/usr/bin/env bash
# Validate a build archive round-trip: extract and diff against the forge
# build tree. Usage:
#   validate-build-archive.sh ARCHIVE_NAME REF_OUT_DIR REF_CACHE_FILE
#     [CART_BIN] [SOURCE_ROOT]
set -euo pipefail

ARCHIVE_NAME="${1:?archive name required (e.g. univocity or create3-factory)}"
REF_OUT_DIR="${2:?reference out/ directory required}"
REF_CACHE_FILE="${3:?reference solidity-files-cache.json path required}"
CART_BIN="${4:-${CART_BIN:-}}"
SOURCE_ROOT="${5:-${SOURCE_ROOT:-$(pwd)}}"

if [ -z "$CART_BIN" ]; then
  CART_BIN="${SOURCE_ROOT}/.cache/univocity-tools/contract-artefacts-linux-x64"
fi
if [ ! -x "$CART_BIN" ]; then
  echo "contract-artefacts binary not found or not executable: $CART_BIN" >&2
  exit 1
fi

WORK_DIR="${WORK_DIR:-${SOURCE_ROOT}/.work}"
REF_DIR="${WORK_DIR}/validate-ref-${ARCHIVE_NAME}"
EXTRACT_DIR="${WORK_DIR}/validate-extract-${ARCHIVE_NAME}"
ARCHIVE_PATH="${WORK_DIR}/${ARCHIVE_NAME}.tar.gz"

rm -rf "$REF_DIR" "$EXTRACT_DIR"
mkdir -p "${REF_DIR}/out" "${REF_DIR}/cache" "$EXTRACT_DIR"

echo "snapshot reference tree for ${ARCHIVE_NAME}"
cp -a "${REF_OUT_DIR}/." "${REF_DIR}/out/"
cp "$REF_CACHE_FILE" "${REF_DIR}/cache/solidity-files-cache.json"

if [ ! -f "$ARCHIVE_PATH" ]; then
  echo "build archive not found: $ARCHIVE_PATH" >&2
  exit 1
fi

echo "extracting ${ARCHIVE_PATH} into ${EXTRACT_DIR}"
"$CART_BIN" archive-extract "$ARCHIVE_NAME.tar.gz" \
  --source-root "$SOURCE_ROOT" \
  --release-root "$EXTRACT_DIR" \
  --verbosity -1

echo "diff out/ trees"
if ! diff -rq "${REF_DIR}/out" "${EXTRACT_DIR}/out"; then
  echo "out/ mismatch after archive-extract for ${ARCHIVE_NAME}" >&2
  exit 1
fi

echo "diff solidity-files-cache.json"
if ! cmp -s "${REF_DIR}/cache/solidity-files-cache.json" \
  "${EXTRACT_DIR}/cache/solidity-files-cache.json"; then
  echo "cache/solidity-files-cache.json mismatch for ${ARCHIVE_NAME}" >&2
  exit 1
fi

BUILD_INFO_DIR="${EXTRACT_DIR}/out/build-info"
if [ -d "$BUILD_INFO_DIR" ]; then
  echo "verify hydrated sources against checkout"
  shopt -s nullglob
  for info in "${BUILD_INFO_DIR}"/*.json; do
    while IFS= read -r source_path; do
      [ -n "$source_path" ] || continue
      extracted="${EXTRACT_DIR}/${source_path}"
      original="${SOURCE_ROOT}/${source_path}"
      if [ ! -f "$extracted" ]; then
        echo "hydrated source missing after extract: ${source_path}" >&2
        exit 1
      fi
      if [ ! -f "$original" ]; then
        echo "checkout source missing for build-info path: ${source_path}" >&2
        exit 1
      fi
      if ! diff -q "$extracted" "$original" >/dev/null; then
        echo "hydrated source differs from checkout: ${source_path}" >&2
        diff -u "$original" "$extracted" >&2 || true
        exit 1
      fi
    done < <(
      jq -r '
        .input.sources // {}
        | to_entries[]
        | select(.value.content != null)
        | .key
      ' "$info"
    )
  done
  shopt -u nullglob
fi

echo "validate-build-archive OK: ${ARCHIVE_NAME}"
