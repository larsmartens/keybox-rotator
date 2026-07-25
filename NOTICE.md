# Third-party notices

Keybox Rotator contains an independently implemented validator and does not
vendor third-party program source code. The following projects and services
materially informed or support its operation.

## Yurii0307/yurikey

- Project: <https://github.com/Yurii0307/yurikey>
- Reference commit during the initial release:
  `628d9d8ee9810b97516574475c0e28cdd6d4c026`
- Declared license: GNU General Public License v3.0
- Use: remote, Base64-encoded keybox candidate feed

The feed is accessed from its `main` branch at runtime. Neither its keybox data
nor private-key material is committed to this repository or bundled in release
archives.

## purainity/keybox-tools

- Project: <https://github.com/purainity/keybox-tools>
- Reference commit during the initial release:
  `199d2ddba42b4335b3a8988778e301c3e9e396cc`
- Declared license: none found as of 2026-07-25
- Use: design reference for chain, private-key, root, and revocation checks

No source code from this project is redistributed. Keybox Rotator's validator
was independently implemented against the file format and Google's public
attestation interfaces.

## TEESimulator-RS

- Project: <https://github.com/Enginex0/TEESimulator-RS>
- Declared license: GNU General Public License v3.0
- Use: compatible consumer of `/data/adb/tricky_store/keybox.xml`

No TEESimulator-RS source code is included.

## Google Android key attestation data

- Documentation:
  <https://developer.android.com/privacy-and-security/security-key-attestation>
- Root certificate set: <https://android.googleapis.com/attestation/root>
- Certificate revocation status:
  <https://android.googleapis.com/attestation/status>

These online interfaces are queried at runtime. Their responses are not bundled
in the repository.
