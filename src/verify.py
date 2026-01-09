"""
Fides Protocol v0.3 - Payment Authorization Verification

Implements the core verification function isPaymentAuthorized()
as defined in Section 7 and Appendix D.

SPDX-License-Identifier: AGPL-3.0-or-later
"""

from datetime import datetime
from decimal import Decimal
from typing import Optional, Union
from uuid import UUID

from .records import DecisionRecord, SpecialDecisionRecord
from .signatures import verify_all_signatures
from .timestamps import is_valid_attestation_method
from .ledger import DecisionRecordLedger
from .payment_ledger import (
    PaymentLedger,
    PaymentRequest,
    PaymentLedgerEntry,
    RejectionReason,
)


class PaymentVerifier:
    """
    Payment authorization verifier.

    Implements the isPaymentAuthorized() function (Section 7.4).
    Verification is:
    - Binary: true/false
    - Deterministic: same input, same output
    - Without interpretation: does not evaluate merit
    - Without implicit exception: no "almost valid"
    """

    def __init__(
        self,
        dr_ledger: DecisionRecordLedger,
        payment_ledger: PaymentLedger,
        executor_id: str,
    ):
        """
        Initialize the verifier.

        Args:
            dr_ledger: The Decision Record ledger
            payment_ledger: The Payment ledger
            executor_id: ID of the Payment Executor
        """
        self.dr_ledger = dr_ledger
        self.payment_ledger = payment_ledger
        self.executor_id = executor_id

    def is_payment_authorized(
        self,
        decision_id: UUID,
        payment: PaymentRequest,
    ) -> tuple[bool, Optional[RejectionReason]]:
        """
        Check if a payment is authorized (Section 7.2, Appendix D).

        Authorization conditions (ALL must be true):
        1. A decision_id is provided (implicit)
        2. The corresponding DR is valid
        3. The DR precedes the payment
        4. The accumulated amount paid <= maximum_value
        5. The payment beneficiary = DR beneficiary
        6. The payment currency = DR currency
        7. The DR has not been revoked
        8. If SDR: payment_date <= maximum_term

        Returns (authorized, rejection_reason).
        """
        # Step 1: Find the Decision Record
        dr = self.dr_ledger.get_decision_record(decision_id)

        if dr is None:
            return False, RejectionReason.DR_NOT_FOUND

        # Step 7: Check if revoked
        if self.dr_ledger.is_revoked(decision_id):
            return False, RejectionReason.DR_REVOKED

        # Step 2: Validate the DR
        is_valid, errors = dr.validate()
        if not is_valid:
            return False, RejectionReason.DR_INVALID

        # Verify signatures
        sigs_valid, invalid_signers = verify_all_signatures(dr)
        if not sigs_valid:
            return False, RejectionReason.SIGNATURE_INVALID

        # Verify timestamp attestation
        if dr.timestamp_attestation:
            if not is_valid_attestation_method(dr.timestamp_attestation.method):
                return False, RejectionReason.TIMESTAMP_INVALID
        # Note: Full attestation verification would require external calls

        # Step 3: DR must precede payment
        if payment.payment_date < dr.decision_date:
            return False, RejectionReason.PAYMENT_BEFORE_DECISION

        # Step 5: Beneficiary must match
        if payment.payment_beneficiary != dr.beneficiary:
            return False, RejectionReason.BENEFICIARY_MISMATCH

        # Step 6: Currency must match
        if payment.payment_currency != dr.currency:
            return False, RejectionReason.CURRENCY_MISMATCH

        # Step 8: SDR expiration check
        if isinstance(dr, SpecialDecisionRecord) and dr.is_sdr:
            if dr.maximum_term and payment.payment_date > dr.maximum_term:
                return False, RejectionReason.SDR_EXPIRED

        # Step 4: Accumulated amount check
        total_paid = self.payment_ledger.sum_authorized_payments(decision_id)
        if (total_paid + payment.payment_amount) > dr.maximum_value:
            return False, RejectionReason.MAXIMUM_VALUE_EXCEEDED

        return True, None

    def execute_payment(
        self,
        decision_id: UUID,
        payment: PaymentRequest,
        bank_callback=None,
    ) -> tuple[bool, PaymentLedgerEntry]:
        """
        Execute a payment with full protocol compliance (Section 7.7.5).

        Correct execution order:
        1. Acquire lock
        2. Verify authorization
        3. Execute at bank (INSIDE LOCK)
        4. Record result
        5. Release lock

        Args:
            decision_id: The DR to pay against
            payment: The payment request
            bank_callback: Optional callback to execute bank transfer
                          Should return (success: bool, confirmation: str)

        Returns (success, payment_entry).
        """
        # Step 1: Acquire exclusive lock
        lock = self.payment_ledger.acquire_lock(decision_id)

        try:
            # Get current chain state for the payment entry
            previous_hash = self.payment_ledger.get_last_payment_hash()

            # Step 2: Verify authorization
            authorized, rejection_reason = self.is_payment_authorized(
                decision_id, payment
            )

            if not authorized:
                # Record rejected payment
                entry = PaymentLedgerEntry.create_rejected(
                    decision_id=decision_id,
                    payment_amount=payment.payment_amount,
                    payment_currency=payment.payment_currency,
                    payment_beneficiary=payment.payment_beneficiary,
                    payment_executor_id=self.executor_id,
                    previous_payment_hash=previous_hash,
                    rejection_reason=rejection_reason,
                )
                self.payment_ledger.record_payment(entry)
                return False, entry

            # Step 3: Execute at bank (INSIDE LOCK)
            if bank_callback:
                bank_success, bank_confirmation = bank_callback(payment)
                if not bank_success:
                    # Record bank failure
                    entry = PaymentLedgerEntry.create_rejected(
                        decision_id=decision_id,
                        payment_amount=payment.payment_amount,
                        payment_currency=payment.payment_currency,
                        payment_beneficiary=payment.payment_beneficiary,
                        payment_executor_id=self.executor_id,
                        previous_payment_hash=previous_hash,
                        rejection_reason=RejectionReason.BANK_EXECUTION_FAILED,
                    )
                    self.payment_ledger.record_payment(entry)
                    return False, entry

            # Step 4: Record success
            entry = PaymentLedgerEntry.create_authorized(
                decision_id=decision_id,
                payment_amount=payment.payment_amount,
                payment_currency=payment.payment_currency,
                payment_beneficiary=payment.payment_beneficiary,
                payment_executor_id=self.executor_id,
                previous_payment_hash=previous_hash,
            )
            self.payment_ledger.record_payment(entry)
            return True, entry

        finally:
            # Step 5: Release lock
            self.payment_ledger.release_lock(lock)


def is_payment_authorized(
    dr_ledger: DecisionRecordLedger,
    payment_ledger: PaymentLedger,
    decision_id: UUID,
    payment: PaymentRequest,
) -> bool:
    """
    Standalone isPaymentAuthorized function (Section 7.4).

    This is the minimal verification interface required by the protocol.
    Returns only true/false.

    Note: This does NOT handle locking. For concurrent payment processing,
    use PaymentVerifier.execute_payment() instead.
    """
    verifier = PaymentVerifier(dr_ledger, payment_ledger, "standalone")
    authorized, _ = verifier.is_payment_authorized(decision_id, payment)
    return authorized
