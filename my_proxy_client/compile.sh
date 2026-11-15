#!/usr/bin/env bash
# compile.sh -- build the my_proxy client into a standalone binary with PyInstaller.
#
# Safe by design:
#   * NEVER deletes build outputs with broad globs (no `rm -rf build dist *.spec`).
#   * PyInstaller's generated spec + cache go into an isolated work dir, so a
#     user-authored ./my_proxy.spec in the repo is left completely untouched.
#   * Uses a pinned PyInstaller version. CI builds with Python 3.11 and
#     PyInstaller 6.11.1; keep them in sync.
#   * Installs nothing implicitly. PyInstaller must already be importable by the
#     chosen interpreter (a virtualenv is recommended). Set ALLOW_PIP_INSTALL=1
#     to install the pinned version into the ACTIVE virtualenv only.
#
# Environment:
#   PYTHON             interpreter to use (default: python3)
#   PYINSTALLER_SPEC   PyInstaller version required for the build (default
#                      6.11.1). Setting this ALSO makes a non-default installed
#                      version an explicit, accepted override.
#   BUILD_DIR          work + cache dir (default <client>/build)
#   OUTPUT_DIR         output dir       (default <client>/dist)
#   ALLOW_PIP_INSTALL  "1" -> pip install the pinned PyInstaller into the venv
#   FORCE              "1"/"true"/"yes" -> rebuild even if the output is newer

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_DIR="$SCRIPT_DIR"
ENTRY="$CLIENT_DIR/my_proxy.py"
PINNED="${PYINSTALLER_SPEC:-6.11.1}"
PIN_EXPLICIT=""
[ -n "${PYINSTALLER_SPEC:-}" ] && PIN_EXPLICIT=1
WORK_DIR="${BUILD_DIR:-$CLIENT_DIR/build}"
OUT_DIR="${OUTPUT_DIR:-$CLIENT_DIR/dist}"
PYTHON="${PYTHON:-python3}"

log() { printf '=== %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
truthy() { case "${1:-}" in 1|true|yes|on) return 0 ;; *) return 1 ;; esac; }

[ -f "$ENTRY" ] || die "entry point not found: $ENTRY"
command -v "$PYTHON" >/dev/null 2>&1 || die "'$PYTHON' not found (set PYTHON=/path/to/python)"

PYVER="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PYEXE="$("$PYTHON" -c 'import sys; print(sys.executable)')"
log "interpreter: $PYEXE (Python $PYVER)"
if [ "$PYVER" != "3.11" ]; then
    printf 'warning: CI builds with Python 3.11 (found %s); binary may differ\n' "$PYVER" >&2
fi

have_pyinstaller() { "$PYTHON" -c 'import PyInstaller' >/dev/null 2>&1; }
installed_version() { "$PYTHON" -c 'import PyInstaller; print(PyInstaller.__version__)' 2>/dev/null || true; }

if ! have_pyinstaller; then
    if [ "${ALLOW_PIP_INSTALL:-0}" = "1" ]; then
        if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.prefix != sys.base_prefix else 1)'; then
            die "ALLOW_PIP_INSTALL=1 but $PYTHON is a system interpreter.
  Create and activate a virtualenv first:
      $PYTHON -m venv .venv && . .venv/bin/activate"
        fi
        log "installing PyInstaller==$PINNED into $PYEXE"
        "$PYTHON" -m pip install --disable-pip-version-check "pyinstaller==$PINNED"
    else
        die "PyInstaller is not importable by $PYTHON.
  Either activate a virtualenv and install it:
      $PYTHON -m venv .venv && . .venv/bin/activate && pip install pyinstaller==$PINNED
  or re-run with ALLOW_PIP_INSTALL=1 (virtualenv only)."
    fi
fi

ACTUAL="$(installed_version)"
if [ -n "$ACTUAL" ] && [ "$ACTUAL" != "$PINNED" ]; then
    if [ -n "$PIN_EXPLICIT" ]; then
        printf 'warning: building with explicitly requested PyInstaller %s (pinned default is %s)\n' "$ACTUAL" "$PINNED" >&2
    else
        die "PyInstaller $ACTUAL is installed but $PINNED is required for CI parity.
  Install the pinned version:
      $PYTHON -m pip install pyinstaller==$PINNED
  or override deliberately:
      PYINSTALLER_SPEC=$ACTUAL $0"
    fi
fi

# Isolated output/work/spec directories. Existing contents are left in place;
# only our own target files are (over)written by PyInstaller itself.
SPEC_DIR="$WORK_DIR/spec"
mkdir -p "$SPEC_DIR" "$WORK_DIR/pyinstaller" "$OUT_DIR"

TARGET="$OUT_DIR/my_proxy"
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) TARGET="$OUT_DIR/my_proxy.exe" ;;
esac

if ! truthy "${FORCE:-}" && [ -f "$TARGET" ] && [ "$TARGET" -nt "$ENTRY" ]; then
    log "up to date: $TARGET (set FORCE=1 to rebuild)"
    exit 0
fi

args=(
    --onefile
    --name my_proxy
    --clean
    --noconfirm
    --workpath "$WORK_DIR/pyinstaller"
    --distpath "$OUT_DIR"
    --specpath "$SPEC_DIR"
    --hidden-import=asyncio
    --hidden-import=json
    --hidden-import=logging
    --hidden-import=argparse
    --hidden-import=dataclasses
    --hidden-import=enum
    --hidden-import=hashlib
    --hidden-import=hmac
    --hidden-import=secrets
    --hidden-import=struct
    --hidden-import=uuid
    --hidden-import=collections
    --hidden-import=pathlib
    --hidden-import=signal
    --hidden-import=typing
)
# --strip needs binutils; skip it rather than failing the build.
if command -v strip >/dev/null 2>&1; then
    args+=(--strip)
fi
args+=("$ENTRY")

log "building with PyInstaller ${ACTUAL:-$PINNED}"
"$PYTHON" -m PyInstaller "${args[@]}"

log "build complete"
printf 'binary: %s\n' "$TARGET"
echo
echo "Try it:"
echo "  $TARGET --help"
echo "  $TARGET authtoken YOUR_TOKEN"
echo "  $TARGET server proxy.example.com:9000"
echo "  $TARGET http 8080"
