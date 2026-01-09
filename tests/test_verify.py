"""
Tests for payment authorization verification.

SPDX-License-Identifier: AGPL-3.0-or-later
"""

import pytest
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from uuid import uuid4

from src.records import (
    DecisionRecord,
    SpecialDecisionRecord,
    ActType,
    ExceptionType,
    Signature,
    SignatureAlgorithm,
)
from src.signatures import generate_keypair, sign_record
from src.ledger import DecisionRecordLedger
from src.payment_ledger import PaymentLedger, PaymentRequest, RejectionReason
from src.verify import PaymentVerifier, is_payment_authorized
from src.hash_chain import GENESIS_HASH


@pytest.fixture
def ledgers():
    """Create in-memory ledgers for testing."""
    dr_ledger = DecisionRecordLedger(":memory:")
    payment_ledger = PaymentLedger(":memory:")
    return dr_ledger, payment_ledger


@pytest.fixture
def verifier(ledgers):
    """Create a payment verifier."""
    dr_ledger, payment_ledger = ledgers
    return PaymentVerifier(dr_ledger, payment_ledger, "EXECUTOR-001")


@pytest.fixture
def sample_dr_with_signature():
    """Create a valid DR with signature."""
    now = datetime.now(timezone.utc)
    private_key, _ = generate_keypair(SignatureAlgorithm.ED25519)

    dr = DecisionRecord(
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

    signature = sign_record(dr, "CPF-12345678901", private_key)
    dr.signatures = [signature]

    return dr


class TestIsPaymentAuthorized:
    """Tests for isPaymentAuthorized function."""

    def test_authorized_valid_payment(self, ledgers, verifier, sample_dr_with_signature):
        """Test authorization for a valid payment."""
        dr_ledger, payment_ledger = ledgers

        # Add DR to ledger
        dr_ledger.append_decision_record(sample_dr_with_signature)

        # Create payment request
        payment = PaymentRequest(
            decision_id=sample_dr_with_signature.decision_id,
            payment_amount=Decimal("5000.00"),
            payment_currency="BRL",
            payment_beneficiary="CNPJ-12345678000199",
            payment_date=datetime.now(timezone.utc),
        )

        authorized, reason = verifier.is_payment_authorized(
            sample_dr_with_signature.decision_id, payment
        )

        assert authorized
        assert reason is None

    def test_rejected_dr_not_found(self, verifier):
        """Test rejection when DR doesn't exist."""
        payment = PaymentRequest(
            decision_id=uuid4(),
            payment_amount=Decimal("5000.00"),
            payment_currency="BRL",
            payment_beneficiary="CNPJ-12345678000199",
            payment_date=datetime.now(timezone.utc),
        )

        authorized, reason = verifier.is_payment_authorized(
            payment.decision_id, payment
        )

        assert not authorized
        assert reason == RejectionReason.DR_NOT_FOUND

    def test_rejected_beneficiary_mismatch(self, ledgers, verifier, sample_dr_with_signature):
        """Test rejection when beneficiary doesn't match."""
        dr_ledger, _ = ledgers
        dr_ledger.append_decision_record(sample_dr_with_signature)

        payment = PaymentRequest(
            decision_id=sample_dr_with_signature.decision_id,
            payment_amount=Decimal("5000.00"),
            payment_currency="BRL",
            payment_beneficiary="WRONG-BENEFICIARY",
            payment_date=datetime.now(timezone.utc),
        )

        authorized, reason = verifier.is_payment_authorized(
            sample_dr_with_signature.decision_id, payment
        )

        assert not authorized
        assert reason == RejectionReason.BENEFICIARY_MISMATCH

    def test_rejected_currency_mismatch(self, ledgers, verifier, sample_dr_with_signature):
        """Test rejection when currency doesn't match."""
        dr_ledger, _ = ledgers
        dr_ledger.append_decision_record(sample_dr_with_signature)

        payment = PaymentRequest(
            decision_id=sample_dr_with_signature.decision_id,
            payment_amount=Decimal("5000.00"),
            payment_currency="USD",  # Wrong currency
            payment_beneficiary="CNPJ-12345678000199",
            payment_date=datetime.now(timezone.utc),
        )

        authorized, reason = verifier.is_payment_authorized(
            sample_dr_with_signature.decision_id, payment
        )

        assert not authorized
        assert reason == RejectionReason.CURRENCY_MISMATCH

    def test_rejected_maximum_value_exceeded(self, ledgers, verifier, sample_dr_with_signature):
        """Test rejection when payment exceeds maximum_value."""
        dr_ledger, _ = ledgers
        dr_ledger.append_decision_record(sample_dr_with_signature)

        payment = PaymentRequest(
            decision_id=sample_dr_with_signature.decision_id,
            payment_amount=Decimal("15000.00"),  # Exceeds 10000 maximum
            payment_currency="BRL",
            payment_beneficiary="CNPJ-12345678000199",
            payment_date=datetime.now(timezone.utc),
        )

        authorized, reason = verifier.is_payment_authorized(
            sample_dr_with_signature.decision_id, payment
        )

        assert not authorized
        assert reason == RejectionReason.MAXIMUM_VALUE_EXCEEDED

    def test_rejected_payment_before_decision(self, ledgers, verifier, sample_dr_with_signature):
        """Test rejection when payment date is before decision date."""
        dr_ledger, _ = ledgers
        dr_ledger.append_decision_record(sample_dr_with_signature)

        payment = PaymentRequest(
            decision_id=sample_dr_with_signature.decision_id,
            payment_amount=Decimal("5000.00"),
            payment_currency="BRL",
            payment_beneficiary="CNPJ-12345678000199",
            payment_date=sample_dr_with_signature.decision_date - timedelta(days=1),
        )

        authorized, reason = verifier.is_payment_authorized(
            sample_dr_with_signature.decision_id, payment
        )

        assert not authorized
        assert reason == RejectionReason.PAYMENT_BEFORE_DECISION


class TestSDRExpiration:
    """Tests for SDR expiration enforcement."""

    def test_rejected_sdr_expired(self, ledgers, verifier):
        """Test rejection when SDR has expired."""
        dr_ledger, _ = ledgers
        now = datetime.now(timezone.utc)
        private_key, _ = generate_keypair(SignatureAlgorithm.ED25519)

        # Create SDR with past expiration
        sdr = SpecialDecisionRecord(
            decision_id=uuid4(),
            authority_id="BR-GOV-001",
            deciders_id=["CPF-12345678901"],
            act_type=ActType.CONTRACT,
            currency="BRL",
            maximum_value=Decimal("10000.00"),
            beneficiary="CNPJ-12345678000199",
            legal_basis="Lei 8.666/1993 Art. 24",
            decision_date=now - timedelta(days=10),
            previous_record_hash=GENESIS_HASH,
            record_timestamp=now - timedelta(days=10),
            signatures=[],
            is_sdr=True,
            exception_type=ExceptionType.HEALTH_EMERGENCY,
            formal_justification="X" * 100,
            maximum_term=now - timedelta(days=1),  # Already expired
            reinforced_deciders=["CPF-12345678901", "CPF-11111111111"],
            oversight_authority="TCU-001",
        )

        signature = sign_record(sdr, "CPF-12345678901", private_key)
        sdr.signatures = [signature]

        dr_ledger.append_decision_record(sdr)

        payment = PaymentRequest(
            decision_id=sdr.decision_id,
            payment_amount=Decimal("5000.00"),
            payment_currency="BRL",
            payment_beneficiary="CNPJ-12345678000199",
            payment_date=now,  # After expiration
        )

        authorized, reason = verifier.is_payment_authorized(
            sdr.decision_id, payment
        )

        assert not authorized
        assert reason == RejectionReason.SDR_EXPIRED


class TestPaymentExecution:
    """Tests for full payment execution flow."""

    def test_execute_successful_payment(self, ledgers, verifier, sample_dr_with_signature):
        """Test successful payment execution."""
        dr_ledger, payment_ledger = ledgers
        dr_ledger.append_decision_record(sample_dr_with_signature)

        payment = PaymentRequest(
            decision_id=sample_dr_with_signature.decision_id,
            payment_amount=Decimal("5000.00"),
            payment_currency="BRL",
            payment_beneficiary="CNPJ-12345678000199",
            payment_date=datetime.now(timezone.utc),
        )

        success, entry = verifier.execute_payment(
            sample_dr_with_signature.decision_id, payment
        )

        assert success
        assert entry.authorization_result
        assert entry.rejection_reason is None

        # Verify recorded in payment ledger
        total = payment_ledger.sum_authorized_payments(
            sample_dr_with_signature.decision_id
        )
        assert total == Decimal("5000.00")

    def test_execute_rejected_payment_recorded(self, ledgers, verifier):
        """Test that rejected payments are recorded in ledger."""
        dr_ledger, payment_ledger = ledgers

        payment = PaymentRequest(
            decision_id=uuid4(),  # Non-existent DR
            payment_amount=Decimal("5000.00"),
            payment_currency="BRL",
            payment_beneficiary="CNPJ-12345678000199",
            payment_date=datetime.now(timezone.utc),
        )

        success, entry = verifier.execute_payment(
            payment.decision_id, payment
        )

        assert not success
        assert not entry.authorization_result
        assert entry.rejection_reason == RejectionReason.DR_NOT_FOUND

        # Verify rejected payment is recorded
        rejected = payment_ledger.get_rejected_payments()
        assert len(rejected) == 1
        assert rejected[0].rejection_reason == RejectionReason.DR_NOT_FOUND

    def test_cumulative_payments_enforced(self, ledgers, verifier, sample_dr_with_signature):
        """Test that cumulative payments respect maximum_value."""
        dr_ledger, payment_ledger = ledgers
        dr_ledger.append_decision_record(sample_dr_with_signature)

        # First payment: 6000
        payment1 = PaymentRequest(
            decision_id=sample_dr_with_signature.decision_id,
            payment_amount=Decimal("6000.00"),
            payment_currency="BRL",
            payment_beneficiary="CNPJ-12345678000199",
            payment_date=datetime.now(timezone.utc),
        )

        success1, _ = verifier.execute_payment(
            sample_dr_with_signature.decision_id, payment1
        )
        assert success1

        # Second payment: 5000 (would exceed 10000 total)
        payment2 = PaymentRequest(
            decision_id=sample_dr_with_signature.decision_id,
            payment_amount=Decimal("5000.00"),
            payment_currency="BRL",
            payment_beneficiary="CNPJ-12345678000199",
            payment_date=datetime.now(timezone.utc),
        )

        success2, entry2 = verifier.execute_payment(
            sample_dr_with_signature.decision_id, payment2
        )

        assert not success2
        assert entry2.rejection_reason == RejectionReason.MAXIMUM_VALUE_EXCEEDED
