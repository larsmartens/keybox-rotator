#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

MODDIR="${0%/*}"
LOG=/data/adb/keybox_rotator/rotator.log

echo "Running full online validation and rotation check..."
sh "$MODDIR/rotate.sh"
STATUS=$?
echo
[ -f "$LOG" ] && tail -n 12 "$LOG"
exit "$STATUS"
