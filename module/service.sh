#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

MODDIR="${0%/*}"
DATA_DIR=/data/adb/keybox_rotator
INTERVAL_FILE="$DATA_DIR/interval_seconds"
DEFAULT_INTERVAL=21600

until [ "$(getprop sys.boot_completed)" = "1" ]; do
    sleep 10
done
sleep 30

while true; do
    sh "$MODDIR/rotate.sh"
    INTERVAL="$DEFAULT_INTERVAL"
    if [ -f "$INTERVAL_FILE" ]; then
        VALUE=$(tr -cd '0-9' < "$INTERVAL_FILE")
        [ -n "$VALUE" ] && [ "$VALUE" -ge 3600 ] 2>/dev/null && INTERVAL="$VALUE"
    fi
    sleep "$INTERVAL"
done
