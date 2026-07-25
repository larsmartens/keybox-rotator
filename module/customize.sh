#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-only

SKIPUNZIP=0
PYTHON=/data/data/com.termux/files/usr/bin/python

ui_print "- Installing CRL-validated Keybox Rotator"
ui_print "- Feed: Yurii0307/yurikey (keybox data is not bundled)"
ui_print "- Trust: Google's live attestation roots and revocation status"
ui_print "- Existing keyboxes are backed up before atomic replacement"
ui_print "- Google app data is never cleared; reboot is never automatic"

[ -x "$PYTHON" ] || abort "! Termux Python is required"
"$PYTHON" -c 'import cryptography' >/dev/null 2>&1 || \
    abort "! Install the Termux python-cryptography package first"

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/rotate.sh" 0 0 0755
set_perm "$MODPATH/check.py" 0 0 0755
set_perm "$MODPATH/fetch.py" 0 0 0755
