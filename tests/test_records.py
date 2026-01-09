"""
Tests for Decision Record, SDR, and Revocation Record.

SPDX-License-Identifier: AGPL-3.0-or-later
"""

import pytest
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from uuid import uuid4

from src.records import (
    DecisionRecord,
    SpecialDecisionRecord,
    RevocationRecord,
    ActType,
    ExceptionType,
    RevocationType,
    Signature,
    SignatureAlgorithm,
)
from src.hash_chain import GENESIS_HASH


@pytest.fixture
def valid_signature():
    """A placeholder signature for testing."""
    return Signature(
        signer_id="CPF-12345678901",
        public_key="dGVzdA==",
        algorithm=SignatureAlgorithm.ED25519,
        signature="dGVzdHNpZw==",
        signed_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def valid_dr(valid_signature):
    """A valid Decision Record for testing."""
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
        signatures=[valid_signature],
    )


class TestDecisionRecord:
    """Tests for DecisionRecord."""

    def test_create_valid_dr(self, valid_dr):
        """Test creating a valid Decision Record."""
        assert valid_dr.decision_id is not None
        assert valid_dr.act_type == ActType.CONTRACT

    def test_validate_valid_dr(self, valid_dr):
        """Test validation passes for valid DR."""
        is_valid, errors = valid_dr.validate()
        assert is_valid
        assert len(errors) == 0

    def test_validate_negative_value(self, valid_dr):
        """Test validation fails for negative maximum_value."""
        valid_dr.maximum_value = Decimal("-100")
        is_valid, errors = valid_dr.validate()
        assert not is_valid
        assert "maximum_value must be positive" in errors

    def test_validate_future_decision_date(self, valid_dr):
        """Test validation fails if decision_date > record_timestamp."""
        valid_dr.decision_date = valid_dr.record_timestamp + timedelta(hours=1)
        is_valid, errors = valid_dr.validate()
        assert not is_valid
        assert "decision_date cannot be after record_timestamp" in errors

    def test_validate_registration_delay_exceeded(self, valid_dr):
        """Test validation fails if registration delay > 72 hours."""
        valid_dr.decision_date = valid_dr.record_timestamp - timedelta(hours=80)
        is_valid, errors = valid_dr.validate()
        assert not is_valid
        assert any("72h" in e for e in errors)

    def test_validate_empty_deciders(self, valid_dr):
        """Test validation fails for empty deciders_id."""
        valid_dr.deciders_id = []
        is_valid, errors = valid_dr.validate()
        assert not is_valid
        assert "deciders_id cannot be empty" in errors

    def test_validate_missing_signature(self, valid_dr):
        """Test validation fails if decider has no signature."""
        valid_dr.deciders_id.append("CPF-99999999999")
        is_valid, errors = valid_dr.validate()
        assert not is_valid
        assert any("Missing signatures" in e for e in errors)

    def test_amendment_requires_references(self, valid_dr, valid_signature):
        """Test amendment type requires references field."""
        valid_dr.act_type = ActType.AMENDMENT
        valid_dr.references = None
        is_valid, errors = valid_dr.validate()
        assert not is_valid
        assert "Amendment requires references field" in errors


class TestSpecialDecisionRecord:
    """Tests for SpecialDecisionRecord (SDR)."""

    def test_create_valid_sdr(self, valid_signature):
        """Test creating a valid SDR."""
        now = datetime.now(timezone.utc)
        sdr = SpecialDecisionRecord(
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
            signatures=[valid_signature],
            is_sdr=True,
            exception_type=ExceptionType.HEALTH_EMERGENCY,
            formal_justification="X" * 100,
            maximum_term=now + timedelta(days=30),
            reinforced_deciders=["CPF-12345678901", "CPF-11111111111"],
            oversight_authority="TCU-001",
        )
        assert sdr.is_sdr
        assert sdr.exception_type == ExceptionType.HEALTH_EMERGENCY

    def test_sdr_requires_formal_justification(self, valid_signature):
        """Test SDR requires 100+ char justification."""
        now = datetime.now(timezone.utc)
        sdr = SpecialDecisionRecord(
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
            signatures=[valid_signature],
            is_sdr=True,
            exception_type=ExceptionType.HEALTH_EMERGENCY,
            formal_justification="Too short",
            maximum_term=now + timedelta(days=30),
            reinforced_deciders=["CPF-12345678901", "CPF-11111111111"],
            oversight_authority="TCU-001",
        )
        is_valid, errors = sdr.validate()
        assert not is_valid
        assert any("100 characters" in e for e in errors)


class TestRevocationRecord:
    """Tests for RevocationRecord."""

    def test_create_valid_rr(self, valid_signature):
        """Test creating a valid Revocation Record."""
        valid_signature.signer_id = "CPF-12345678901"
        rr = RevocationRecord.create(
            target_decision_id=uuid4(),
            revocation_type=RevocationType.VOLUNTARY,
            revocation_reason="X" * 50,
            revoker_authority="original_decider",
            revoker_id=["CPF-12345678901"],
            previous_record_hash=GENESIS_HASH,
        )
        rr.signatures = [valid_signature]
        is_valid, errors = rr.validate()
        assert is_valid

    def test_rr_requires_reason_50_chars(self, valid_signature):
        """Test RR requires 50+ char reason."""
        valid_signature.signer_id = "CPF-12345678901"
        rr = RevocationRecord.create(
            target_decision_id=uuid4(),
            revocation_type=RevocationType.VOLUNTARY,
            revocation_reason="Too short",
            revoker_authority="original_decider",
            revoker_id=["CPF-12345678901"],
            previous_record_hash=GENESIS_HASH,
        )
        rr.signatures = [valid_signature]
        is_valid, errors = rr.validate()
        assert not is_valid
        assert any("50 characters" in e for e in errors)
