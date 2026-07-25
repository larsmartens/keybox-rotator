# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import importlib.util
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

MODULE_PATH = Path(__file__).parents[1] / "module" / "check.py"
SPEC = importlib.util.spec_from_file_location("keybox_check", MODULE_PATH)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def certificate(
    subject: x509.Name,
    issuer: x509.Name,
    public_key,
    issuer_key,
    serial: int,
    *,
    is_ca: bool,
) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


def add_keybox_entry(parent, algorithm, private_key, leaf, root):
    key_node = ET.SubElement(parent, "Key", algorithm=algorithm)
    private_node = ET.SubElement(key_node, "PrivateKey")
    private_node.text = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    chain_node = ET.SubElement(key_node, "CertificateChain")
    for item in (leaf, root):
        certificate_node = ET.SubElement(chain_node, "Certificate")
        certificate_node.text = item.public_bytes(serialization.Encoding.PEM).decode()


def build_keybox(*, mismatched_rsa=False):
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test root")])
    root = certificate(root_name, root_name, root_key.public_key(), root_key, 100, is_ca=True)

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_leaf = certificate(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RSA leaf")]),
        root_name,
        rsa_key.public_key(),
        root_key,
        101,
        is_ca=False,
    )
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_leaf = certificate(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ECDSA leaf")]),
        root_name,
        ec_key.public_key(),
        root_key,
        102,
        is_ca=False,
    )

    document = ET.Element("AndroidAttestation")
    ET.SubElement(document, "NumberOfKeyboxes").text = "1"
    keybox = ET.SubElement(document, "Keybox")
    stored_rsa_key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if mismatched_rsa
        else rsa_key
    )
    add_keybox_entry(keybox, "rsa", stored_rsa_key, rsa_leaf, root)
    add_keybox_entry(keybox, "ecdsa", ec_key, ec_leaf, root)
    return ET.tostring(document), root, rsa_leaf


class KeyboxValidationTests(unittest.TestCase):
    def validate(self, xml_bytes, root, status):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.xml"
            path.write_bytes(xml_bytes)
            roots = [root.public_bytes(serialization.Encoding.PEM).decode()]
            with (
                mock.patch.object(CHECK, "drop_to_termux_network_uid"),
                mock.patch.object(CHECK, "fetch_json", side_effect=[roots, status]),
            ):
                return CHECK.validate_keybox(path)

    def test_accepts_complete_clean_pair(self):
        xml_bytes, root, _ = build_keybox()
        self.assertEqual(
            self.validate(xml_bytes, root, {"entries": {}}),
            {"RSA", "ECDSA"},
        )

    def test_rejects_revoked_certificate(self):
        xml_bytes, root, rsa_leaf = build_keybox()
        serial = format(rsa_leaf.serial_number, "x")
        with self.assertRaisesRegex(CHECK.ValidationError, "revoked"):
            self.validate(
                xml_bytes,
                root,
                {"entries": {serial: {"status": "REVOKED", "reason": "KEY_COMPROMISE"}}},
            )

    def test_rejects_private_key_mismatch(self):
        xml_bytes, root, _ = build_keybox(mismatched_rsa=True)
        with self.assertRaisesRegex(CHECK.ValidationError, "does not match"):
            self.validate(xml_bytes, root, {"entries": {}})


if __name__ == "__main__":
    unittest.main()
