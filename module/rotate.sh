#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

MODDIR="${0%/*}"
DATA_DIR=/data/adb/keybox_rotator
BACKUP_DIR="$DATA_DIR/backups"
TRICKY_DIR=/data/adb/tricky_store
ACTIVE="$TRICKY_DIR/keybox.xml"
PYTHON=/data/data/com.termux/files/usr/bin/python
TERMUX_DATA=/data/data/com.termux/files
SOURCE_URL=https://raw.githubusercontent.com/Yurii0307/yurikey/main/key
LOG="$DATA_DIR/rotator.log"
LOCK="$DATA_DIR/.lock"

umask 077
mkdir -p "$DATA_DIR" "$BACKUP_DIR" "$TRICKY_DIR"
chmod 0700 "$DATA_DIR" "$BACKUP_DIR"

log_line() {
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG"
    tail -n 200 "$LOG" > "$LOG.tmp" 2>/dev/null && mv -f "$LOG.tmp" "$LOG"
    chmod 0600 "$LOG" 2>/dev/null
}

if ! mkdir "$LOCK" 2>/dev/null; then
    log_line "rotation already running"
    exit 0
fi

CANDIDATE="$DATA_DIR/candidate.$$.xml"
cleanup() {
    rm -f "$CANDIDATE"
    rmdir "$LOCK" 2>/dev/null
}
trap cleanup EXIT HUP INT TERM

if [ ! -x "$PYTHON" ] || ! "$PYTHON" -c 'import cryptography' >/dev/null 2>&1; then
    log_line "failed: Termux Python with cryptography is unavailable"
    exit 1
fi

validate() {
    "$PYTHON" "$MODDIR/check.py" "$1" >/dev/null 2>&1
}

if [ -s "$ACTIVE" ] && validate "$ACTIVE"; then
    log_line "active keybox is fully valid; no rotation"
    exit 0
fi

TERMUX_UID=$(stat -c '%u' "$TERMUX_DATA" 2>/dev/null)
case "$TERMUX_UID" in
    ''|*[!0-9]*)
        log_line "failed: could not resolve Termux UID"
        exit 1
        ;;
esac

log_line "active keybox invalid or revoked; fetching candidate"
if ! su -g "$TERMUX_UID" -G 3003 "$TERMUX_UID" -c \
    "$PYTHON $MODDIR/fetch.py $SOURCE_URL" > "$CANDIDATE"; then
    log_line "failed: candidate download or decode"
    exit 1
fi

if ! validate "$CANDIDATE"; then
    log_line "failed closed: candidate did not pass full live validation"
    exit 1
fi

if [ -s "$ACTIVE" ]; then
    STAMP=$(date '+%Y%m%d-%H%M%S')
    BACKUP="$BACKUP_DIR/keybox.$STAMP.xml"
    if ! cp -p "$ACTIVE" "$BACKUP"; then
        log_line "failed closed: could not back up active keybox"
        exit 1
    fi
    chmod 0600 "$BACKUP"
fi

NEW="$TRICKY_DIR/.keybox.xml.new.$$"
if ! cp "$CANDIDATE" "$NEW"; then
    log_line "failed: could not stage candidate"
    exit 1
fi
chown 0:0 "$NEW"
chmod 0644 "$NEW"
if ! mv -f "$NEW" "$ACTIVE"; then
    rm -f "$NEW"
    log_line "failed: atomic keybox replacement"
    exit 1
fi

log_line "installed fully validated Google-rooted keybox"
su -lp 2000 -c "cmd notification post -t 'Keybox Rotator' keybox_rotator 'Installed a CRL-valid keybox for TEESimulator.'" >/dev/null 2>&1 || true
exit 0
