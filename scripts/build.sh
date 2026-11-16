#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
: "${OPENWRT_DIR:?OPENWRT_DIR must point to the prepared build tree}"
JOBS=${BUILD_JOBS:-4}
mkdir -p "$ROOT/logs"
cd "$OPENWRT_DIR"

make defconfig 2>&1 | tee "$ROOT/logs/defconfig.log"
python3 "$ROOT/scripts/verify.py" config "$OPENWRT_DIR/.config"
make -j8 download 2>&1 | tee "$ROOT/logs/download.log"
if ! make -j"$JOBS" BUILD_LOG=1 2>&1 | tee "$ROOT/logs/build.log"; then
  make -j1 V=s BUILD_LOG=1 2>&1 | tee "$ROOT/logs/build-serial.log"
fi
python3 "$ROOT/scripts/verify.py" kernel "$OPENWRT_DIR"
