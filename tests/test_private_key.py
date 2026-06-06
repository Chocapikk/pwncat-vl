"""
Unit tests for the private-key classification helper used by the
``creds.private_key`` enumerate module.

We generate keys on the fly with the ``cryptography`` library so the
tests stay deterministic and do not rely on any fixture key on disk.
"""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from pwncat.modules.linux.enumerate.creds.private_key import _classify_key


def _make_rsa_pem(encrypted: bool = False) -> str:
    """Generate a 2048-bit RSA key in PKCS8 PEM form."""

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if encrypted:
        algo = serialization.BestAvailableEncryption(b"hunter2")
    else:
        algo = serialization.NoEncryption()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        algo,
    )
    return pem.decode()


def _make_ed25519_openssh(encrypted: bool = False) -> str:
    """Generate an ed25519 key in OpenSSH private-key form."""

    key = ed25519.Ed25519PrivateKey.generate()
    if encrypted:
        algo = serialization.BestAvailableEncryption(b"hunter2")
    else:
        algo = serialization.NoEncryption()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        algo,
    )
    return pem.decode()


class TestClassifyKey:
    def test_unencrypted_rsa_pem_is_valid(self):
        valid, encrypted = _classify_key(_make_rsa_pem(encrypted=False))
        assert valid is True
        assert encrypted is False

    def test_encrypted_rsa_pem_is_flagged(self):
        valid, encrypted = _classify_key(_make_rsa_pem(encrypted=True))
        assert valid is True
        assert encrypted is True

    def test_unencrypted_openssh_ed25519_is_valid(self):
        valid, encrypted = _classify_key(_make_ed25519_openssh(encrypted=False))
        assert valid is True
        assert encrypted is False

    def test_encrypted_openssh_ed25519_is_flagged(self):
        valid, encrypted = _classify_key(_make_ed25519_openssh(encrypted=True))
        assert valid is True
        assert encrypted is True

    def test_random_garbage_is_invalid(self):
        valid, encrypted = _classify_key("not a private key at all")
        assert valid is False
        assert encrypted is False

    def test_empty_input_is_invalid(self):
        valid, encrypted = _classify_key("")
        assert valid is False
        assert encrypted is False

    @pytest.mark.parametrize("payload", ["\x00\x01\x02", "BEGIN RSA without anything"])
    def test_malformed_payloads_are_invalid(self, payload):
        valid, encrypted = _classify_key(payload)
        assert valid is False
        assert encrypted is False
