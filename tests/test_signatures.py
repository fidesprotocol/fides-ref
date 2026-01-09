"""
Tests for cryptographic signatures.

SPDX-License-Identifier: AGPL-3.0-or-later
"""

import pytest
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from uuid import uuid4

from src.signatures import (
    generate_keypair,
    sign_record,
    verify_signature,
    verify_all_signatures,
    public_key_to_base64,
    base64_to_public_key,
)
from src.records import (
    DecisionRecord,
    ActType,
    SignatureAlgorithm,
)
from src.hash_chain import GENESIS_HASH


@pytest.fixture
def sample_dr():
    """A sample Decision Record for signing tests."""
    now = datetime.now(timezone.utc)
    return DecisionRecord(
        decision_id=uuid4(),
        authority_id="BR-GOV-001",
        deciders_id=["CPF-12345678901"],
        act_type=ActType.CONTRACT,
        currency="BRL",
        maximum_value=Decimal("10000.00"),
        beneficiary="CNPJ-12345678000199",
        legal_basis="Lei 8.666/1993 Art. 24",
        decision_date=now - timedelta(minutes=30),
        previous_record_hash=GENESIS_HASH,
        record_timestamp=now,
        signatures=[],
    )


class TestKeyGeneration:
    """Tests for key pair generation."""

    def test_generate_ed25519_keypair(self):
        """Test Ed25519 key generation."""
        private_key, public_key = generate_keypair(SignatureAlgorithm.ED25519)
        assert private_key is not None
        assert public_key is not None

    def test_generate_ecdsa_p256_keypair(self):
        """Test ECDSA P-256 key generation."""
        private_key, public_key = generate_keypair(SignatureAlgorithm.ECDSA_P256)
        assert private_key is not None
        assert public_key is not None

    def test_generate_ecdsa_p384_keypair(self):
        """Test ECDSA P-384 key generation."""
        private_key, public_key = generate_keypair(SignatureAlgorithm.ECDSA_P384)
        assert private_key is not None
        assert public_key is not None

    def test_generate_rsa_pss_keypair(self):
        """Test RSA-PSS key generation."""
        private_key, public_key = generate_keypair(SignatureAlgorithm.RSA_PSS)
        assert private_key is not None
        assert public_key is not None


class TestPublicKeySerialization:
    """Tests for public key serialization."""

    def test_ed25519_roundtrip(self):
        """Test Ed25519 public key serialization roundtrip."""
        _, public_key = generate_keypair(SignatureAlgorithm.ED25519)
        b64 = public_key_to_base64(public_key)
        restored = base64_to_public_key(b64)
        # Verify by comparing serialized forms
        assert public_key_to_base64(restored) == b64

    def test_ecdsa_roundtrip(self):
        """Test ECDSA public key serialization roundtrip."""
        _, public_key = generate_keypair(SignatureAlgorithm.ECDSA_P256)
        b64 = public_key_to_base64(public_key)
        restored = base64_to_public_key(b64)
        assert public_key_to_base64(restored) == b64


class TestSignAndVerify:
    """Tests for record signing and verification."""

    def test_sign_and_verify_ed25519(self, sample_dr):
        """Test signing and verifying with Ed25519."""
        private_key, _ = generate_keypair(SignatureAlgorithm.ED25519)

        signature = sign_record(
            sample_dr,
            signer_id="CPF-12345678901",
            private_key=private_key,
            algorithm=SignatureAlgorithm.ED25519,
        )

        sample_dr.signatures = [signature]
        assert verify_signature(sample_dr, signature)

    def test_sign_and_verify_ecdsa_p256(self, sample_dr):
        """Test signing and verifying with ECDSA P-256."""
        private_key, _ = generate_keypair(SignatureAlgorithm.ECDSA_P256)

        signature = sign_record(
            sample_dr,
            signer_id="CPF-12345678901",
            private_key=private_key,
            algorithm=SignatureAlgorithm.ECDSA_P256,
        )

        sample_dr.signatures = [signature]
        assert verify_signature(sample_dr, signature)

    def test_modified_record_fails_verification(self, sample_dr):
        """Test that modifying a record invalidates the signature."""
        private_key, _ = generate_keypair(SignatureAlgorithm.ED25519)

        signature = sign_record(
            sample_dr,
            signer_id="CPF-12345678901",
            private_key=private_key,
        )

        # Modify the record after signing
        sample_dr.maximum_value = Decimal("99999.99")
        sample_dr.signatures = [signature]

        # Verification should fail
        assert not verify_signature(sample_dr, signature)

    def test_wrong_public_key_fails_verification(self, sample_dr):
        """Test that wrong public key fails verification."""
        private_key1, _ = generate_keypair(SignatureAlgorithm.ED25519)
        _, public_key2 = generate_keypair(SignatureAlgorithm.ED25519)

        signature = sign_record(
            sample_dr,
            signer_id="CPF-12345678901",
            private_key=private_key1,
        )

        # Replace public key with wrong one
        signature.public_key = public_key_to_base64(public_key2)
        sample_dr.signatures = [signature]

        assert not verify_signature(sample_dr, signature)


class TestVerifyAllSignatures:
    """Tests for verifying all signatures on a record."""

    def test_all_valid_signatures(self, sample_dr):
        """Test verification passes when all signatures are valid."""
        private_key, _ = generate_keypair(SignatureAlgorithm.ED25519)

        signature = sign_record(
            sample_dr,
            signer_id="CPF-12345678901",
            private_key=private_key,
        )

        sample_dr.signatures = [signature]
        all_valid, invalid_signers = verify_all_signatures(sample_dr)

        assert all_valid
        assert len(invalid_signers) == 0

    def test_mixed_valid_invalid_signatures(self, sample_dr):
        """Test detection of invalid signatures among valid ones."""
        private_key1, _ = generate_keypair(SignatureAlgorithm.ED25519)
        private_key2, _ = generate_keypair(SignatureAlgorithm.ED25519)

        # Valid signature
        sig1 = sign_record(
            sample_dr,
            signer_id="CPF-12345678901",
            private_key=private_key1,
        )

        # Invalid signature (signed with different key but claims same signer)
        sig2 = sign_record(
            sample_dr,
            signer_id="CPF-99999999999",
            private_key=private_key2,
        )
        # Corrupt the signature
        sig2.signature = "aW52YWxpZA=="

        sample_dr.deciders_id = ["CPF-12345678901", "CPF-99999999999"]
        sample_dr.signatures = [sig1, sig2]

        all_valid, invalid_signers = verify_all_signatures(sample_dr)

        assert not all_valid
        assert "CPF-99999999999" in invalid_signers
