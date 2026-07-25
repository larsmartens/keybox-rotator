#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Fail-closed validator for Android attestation keybox XML files."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    padding,
    rsa,
)

ROOTS_URL = "https://android.googleapis.com/attestation/root"
STATUS_URL = "https://android.googleapis.com/attestation/status"
MAX_KEYBOX_BYTES = 512 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
NETWORK_TIMEOUT_SECONDS = 15
REQUIRED_ALGORITHMS = frozenset({"RSA", "ECDSA"})
TERMUX_CA_FILE = "/data/data/com.termux/files/usr/etc/tls/cert.pem"
TERMUX_DATA_DIR = "/data/data/com.termux/files"
ANDROID_INET_GID = 3003


class ValidationError(RuntimeError):
    """Raised when a keybox does not satisfy every validation requirement."""


def drop_to_termux_network_uid() -> None:
    """Drop root before HTTPS so traffic uses Termux's normal VPN policy."""
    if os.getuid() != 0:
        return
    try:
        termux_uid = os.stat(TERMUX_DATA_DIR).st_uid
        libc = ctypes.CDLL(None, use_errno=True)
        groups = (ctypes.c_uint * 1)(ANDROID_INET_GID)
        calls = (
            ("setgroups", (1, groups)),
            ("setgid", (termux_uid,)),
            ("setuid", (termux_uid,)),
        )
        for function_name, arguments in calls:
            if getattr(libc, function_name)(*arguments) != 0:
                error_number = ctypes.get_errno()
                raise OSError(error_number, os.strerror(error_number))
    except OSError as error:
        raise ValidationError("could not drop to the Termux network identity") from error


def fetch_json(url: str) -> Any:
    query = urllib.parse.urlencode({"ts": int(time.time())})
    request = urllib.request.Request(
        f"{url}?{query}",
        headers={
            "Accept": "application/json",
            "Cache-Control": "no-cache, no-store, max-age=0",
            "Pragma": "no-cache",
            "User-Agent": "keybox-rotator/1.0",
        },
    )
    ca_file = os.environ.get("SSL_CERT_FILE")
    if not ca_file or not Path(ca_file).is_file():
        ca_file = TERMUX_CA_FILE if Path(TERMUX_CA_FILE).is_file() else None
    ssl_context = ssl.create_default_context(cafile=ca_file)
    with urllib.request.urlopen(
        request,
        timeout=NETWORK_TIMEOUT_SECONDS,
        context=ssl_context,
    ) as response:
        if response.status != 200:
            raise ValidationError(f"{url} returned HTTP {response.status}")
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ValidationError(f"response from {url} exceeded size limit")
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"invalid JSON from {url}") from error


def root_key_fingerprint(certificate: x509.Certificate) -> bytes:
    return hashlib.sha256(public_key_bytes(certificate.public_key())).digest()


def load_google_roots(payload: Any) -> set[bytes]:
    if not isinstance(payload, list) or not payload:
        raise ValidationError("Google root response was not a non-empty array")

    fingerprints: set[bytes] = set()
    for value in payload:
        if not isinstance(value, str):
            raise ValidationError("Google root response contained a non-string entry")
        try:
            certificate = x509.load_pem_x509_certificate(value.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as error:
            raise ValidationError("Google root response contained an invalid certificate") from error
        fingerprints.add(root_key_fingerprint(certificate))
    return fingerprints


def load_revocations(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), dict):
        raise ValidationError("Google revocation response did not contain an entries object")
    return payload["entries"]


def public_key_bytes(key: Any) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_signature(certificate: x509.Certificate, issuer_key: Any) -> None:
    signature = certificate.signature
    signed_data = certificate.tbs_certificate_bytes

    try:
        if isinstance(issuer_key, rsa.RSAPublicKey):
            parameters = certificate.signature_algorithm_parameters
            if parameters is None:
                parameters = padding.PKCS1v15()
            issuer_key.verify(signature, signed_data, parameters, certificate.signature_hash_algorithm)
        elif isinstance(issuer_key, ec.EllipticCurvePublicKey):
            issuer_key.verify(
                signature,
                signed_data,
                ec.ECDSA(certificate.signature_hash_algorithm),
            )
        elif isinstance(issuer_key, dsa.DSAPublicKey):
            issuer_key.verify(signature, signed_data, certificate.signature_hash_algorithm)
        elif isinstance(issuer_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            issuer_key.verify(signature, signed_data)
        else:
            raise ValidationError("unsupported certificate issuer key type")
    except ValidationError:
        raise
    except Exception as error:
        raise ValidationError("certificate signature verification failed") from error


def certificate_time_bounds(certificate: x509.Certificate) -> tuple[datetime, datetime]:
    before = getattr(certificate, "not_valid_before_utc", None)
    after = getattr(certificate, "not_valid_after_utc", None)
    if before is None:
        before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
    if after is None:
        after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
    return before, after


def assert_not_revoked(certificate: x509.Certificate, entries: dict[str, Any]) -> None:
    serial_hex = format(certificate.serial_number, "x").lower()
    serial_decimal = str(certificate.serial_number)
    entry = entries.get(serial_hex) or entries.get(serial_hex.upper()) or entries.get(serial_decimal)
    if entry is not None:
        reason = entry.get("reason", "unspecified") if isinstance(entry, dict) else "unspecified"
        raise ValidationError(f"certificate is listed by Google as revoked ({reason})")


def parse_certificates(chain_node: ET.Element) -> list[x509.Certificate]:
    certificates: list[x509.Certificate] = []
    for node in chain_node.findall("./Certificate"):
        value = (node.text or "").strip()
        if not value:
            raise ValidationError("certificate chain contained an empty certificate")
        try:
            certificates.append(x509.load_pem_x509_certificate(value.encode("ascii")))
        except (ValueError, UnicodeEncodeError) as error:
            raise ValidationError("certificate chain contained invalid PEM") from error
    if len(certificates) < 2:
        raise ValidationError("certificate chain must contain at least leaf and root certificates")
    return certificates


def validate_chain(
    certificates: list[x509.Certificate],
    trusted_roots: set[bytes],
    revocations: dict[str, Any],
) -> None:
    now = datetime.now(timezone.utc)
    for certificate in certificates:
        not_before, not_after = certificate_time_bounds(certificate)
        if not_before > now or now > not_after:
            raise ValidationError("certificate chain contains an expired or not-yet-valid certificate")
        assert_not_revoked(certificate, revocations)

    for child, issuer in zip(certificates, certificates[1:]):
        if child.issuer != issuer.subject:
            raise ValidationError("certificate issuer/subject linkage is invalid")
        verify_signature(child, issuer.public_key())

    root = certificates[-1]
    if root.issuer != root.subject:
        raise ValidationError("root certificate is not self-issued")
    verify_signature(root, root.public_key())
    if root_key_fingerprint(root) not in trusted_roots:
        raise ValidationError("chain is not anchored in Google's current attestation roots")


def normalize_algorithm(value: str) -> str:
    algorithm = value.strip().upper()
    if algorithm == "EC":
        return "ECDSA"
    return algorithm


def validate_key_entry(
    key_node: ET.Element,
    trusted_roots: set[bytes],
    revocations: dict[str, Any],
) -> str:
    algorithm = normalize_algorithm(key_node.get("algorithm", ""))
    if algorithm not in REQUIRED_ALGORITHMS:
        raise ValidationError(f"unsupported or missing key algorithm: {algorithm or 'empty'}")

    private_node = key_node.find("./PrivateKey")
    chain_node = key_node.find("./CertificateChain")
    if private_node is None or chain_node is None or not (private_node.text or "").strip():
        raise ValidationError(f"{algorithm} entry is missing private key or certificate chain")

    try:
        private_key = serialization.load_pem_private_key(
            (private_node.text or "").strip().encode("ascii"),
            password=None,
        )
    except (ValueError, TypeError, UnicodeEncodeError) as error:
        raise ValidationError(f"{algorithm} private key is invalid") from error

    if algorithm == "RSA" and not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValidationError("RSA entry does not contain an RSA private key")
    if algorithm == "ECDSA" and not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValidationError("ECDSA entry does not contain an EC private key")

    certificates = parse_certificates(chain_node)
    if public_key_bytes(private_key.public_key()) != public_key_bytes(certificates[0].public_key()):
        raise ValidationError(f"{algorithm} private key does not match its leaf certificate")

    validate_chain(certificates, trusted_roots, revocations)
    return algorithm


def validate_keybox(path: Path) -> set[str]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ValidationError(f"cannot read keybox: {error}") from error
    if size <= 0 or size > MAX_KEYBOX_BYTES:
        raise ValidationError("keybox is empty or exceeds the size limit")

    try:
        root_node = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as error:
        raise ValidationError("keybox XML could not be parsed") from error
    if root_node.tag != "AndroidAttestation":
        raise ValidationError("unexpected keybox root element")

    drop_to_termux_network_uid()
    trusted_roots = load_google_roots(fetch_json(ROOTS_URL))
    revocations = load_revocations(fetch_json(STATUS_URL))

    algorithms: set[str] = set()
    key_nodes = root_node.findall("./Keybox/Key") or root_node.findall(".//Key")
    if not key_nodes:
        raise ValidationError("keybox contains no key entries")
    for key_node in key_nodes:
        algorithm = validate_key_entry(key_node, trusted_roots, revocations)
        if algorithm in algorithms:
            raise ValidationError(f"keybox contains duplicate {algorithm} entries")
        algorithms.add(algorithm)

    if algorithms != REQUIRED_ALGORITHMS:
        missing = ", ".join(sorted(REQUIRED_ALGORITHMS - algorithms))
        raise ValidationError(f"keybox is missing required algorithm(s): {missing}")
    return algorithms


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("keybox", type=Path, help="path to keybox.xml")
    arguments = parser.parse_args()

    try:
        algorithms = validate_keybox(arguments.keybox)
    except ValidationError as error:
        print(f"INVALID: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        print(f"INVALID: online validation failed closed ({error})", file=sys.stderr)
        return 1

    print(f"VALID: Google-rooted, CRL-clean {','.join(sorted(algorithms))} keybox")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
