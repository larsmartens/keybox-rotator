# Keybox Rotator

[![CI](https://github.com/larsmartens/keybox-rotator/actions/workflows/ci.yml/badge.svg)](https://github.com/larsmartens/keybox-rotator/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

Keybox Rotator is a deliberately narrow KernelSU/Magisk-style module for
TEESimulator-compatible Android setups. It replaces an attestation keybox only
after the active file fails a complete online validation. It does not change
build properties, clear Google app data, alter the target list, or reboot the
device.

No keybox or private key is stored in this repository or release archives.

## What it validates

Before accepting a keybox, the module requires all of the following:

- one RSA entry and one ECDSA entry;
- parseable private keys that match their leaf certificates;
- correct issuer/subject linkage and signatures across every certificate chain;
- currently valid certificates throughout each chain;
- self-signed roots whose public keys match Google's live attestation root set;
- no certificate serial present in Google's live revocation status list.

Both Google responses must be available and valid. Network, TLS, parsing, or
validation failures are fail-closed: the active keybox is left untouched.

## Rotation flow

1. Wait for Android boot completion, then validate the active keybox.
2. If it is fully valid, make no change.
3. Otherwise, download the current Base64-encoded candidate from the
   [Yurii0307/yurikey](https://github.com/Yurii0307/yurikey) feed.
4. Run the same complete validation against the candidate.
5. Back up the existing keybox and replace it atomically.

The default interval is six hours. The module keeps a bounded 200-line audit
log and never clears application data or reboots automatically.

## Requirements

- a rooted Android device using KernelSU, Magisk, or a compatible module loader;
- TEESimulator-RS or another component that reads
  `/data/adb/tricky_store/keybox.xml`;
- [Termux](https://termux.dev/) installed at its standard application path;
- Termux Python and `cryptography`:

```sh
pkg install python python-cryptography
```

- outbound HTTPS access to GitHub raw content and Google's Android attestation
  endpoints.

The network requests run with Termux's Android UID and `inet` group after the
keybox is parsed. This avoids running HTTPS as root and respects the normal
per-app VPN path on Android.

## Installation

Download `keybox-rotator-v1.0.1.zip` from the
[latest release](https://github.com/larsmartens/keybox-rotator/releases/latest),
install it through your root manager, and reboot once so the service becomes
persistent.

On KernelSU, an equivalent CLI installation is:

```sh
su -c '/data/adb/ksu/bin/ksud module install /path/to/keybox-rotator-v1.0.1.zip'
```

The module action button runs an immediate validation/rotation pass.

## Configuration and recovery

Runtime state is kept outside the module directory:

| Path | Purpose |
| --- | --- |
| `/data/adb/keybox_rotator/rotator.log` | Bounded audit log |
| `/data/adb/keybox_rotator/backups/` | Pre-replacement keybox backups |
| `/data/adb/keybox_rotator/interval_seconds` | Optional interval override |

The interval override must contain an integer of at least `3600`. Uninstalling
the module preserves logs and backups intentionally; remove that directory
manually only after confirming it is no longer needed.

## Security boundaries

This project reduces the chance of installing malformed, expired, untrusted, or
already-revoked material. It cannot make a public keybox private, prevent its
future revocation, or guarantee a Play Integrity verdict. Google can revoke
leaked attestation keys at any time.

Treat keybox files and backups as secrets. Do not attach them to issues, commit
them to a repository, or paste their contents into logs.

## Attribution

- The remote candidate feed is maintained by
  [Yurii0307/yurikey](https://github.com/Yurii0307/yurikey) under GPL-3.0. Feed
  data is fetched at runtime and is not redistributed here.
- The validation approach was informed by
  [purainity/keybox-tools](https://github.com/purainity/keybox-tools). Its
  validator is not included because that repository does not currently declare
  a software license; this project ships an independent implementation.
- The module integrates with
  [Enginex0/TEESimulator-RS](https://github.com/Enginex0/TEESimulator-RS), but
  does not include its source code.
- Trust anchors and revocation status come from Google's official
  [Android key attestation documentation](https://developer.android.com/privacy-and-security/security-key-attestation),
  [root endpoint](https://android.googleapis.com/attestation/root), and
  [status endpoint](https://android.googleapis.com/attestation/status).

See [NOTICE.md](NOTICE.md) for exact upstream references.

## License

Copyright © 2026 Lars Martens. Released under the
[GNU General Public License v3.0 only](LICENSE).
