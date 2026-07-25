#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Download and decode one bounded keybox feed response to stdout."""

from __future__ import annotations

import argparse
import base64
import binascii
import ssl
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_ENCODED_BYTES = 1024 * 1024
MAX_DECODED_BYTES = 512 * 1024
TERMUX_CA_FILE = "/data/data/com.termux/files/usr/etc/tls/cert.pem"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    arguments = parser.parse_args()

    context = ssl.create_default_context(
        cafile=TERMUX_CA_FILE if Path(TERMUX_CA_FILE).is_file() else None
    )
    request = urllib.request.Request(
        arguments.url,
        headers={"Cache-Control": "no-cache", "User-Agent": "keybox-rotator/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20, context=context) as response:
            if response.status != 200:
                raise RuntimeError(f"feed returned HTTP {response.status}")
            encoded = response.read(MAX_ENCODED_BYTES + 1).strip()
        if len(encoded) > MAX_ENCODED_BYTES:
            raise RuntimeError("feed response exceeded size limit")
        decoded = base64.b64decode(encoded, validate=True)
        if not decoded or len(decoded) > MAX_DECODED_BYTES:
            raise RuntimeError("decoded keybox was empty or exceeded size limit")
        root = ET.fromstring(decoded)
        if root.tag != "AndroidAttestation" or not root.findall(".//PrivateKey"):
            raise RuntimeError("feed response was not an Android attestation keybox")
    except (OSError, RuntimeError, ValueError, binascii.Error, ET.ParseError) as error:
        print(f"download failed: {error}", file=sys.stderr)
        return 1

    sys.stdout.buffer.write(decoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
