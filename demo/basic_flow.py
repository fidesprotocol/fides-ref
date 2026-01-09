#!/usr/bin/env python3
"""
Fides Protocol v0.3 - Basic Flow Demo

Demonstrates the complete flow of:
1. Creating a Decision Record
2. Signing the record
3. Adding to the append-only ledger
4. Authorizing and executing a payment
5. Attempting a payment that exceeds the limit

SPDX-License-Identifier: AGPL-3.0-or-later
"""

import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from datetime import datetime, timezone, timedelta
from decimal import Decimal
from uuid import uuid4

from src.records import DecisionRecord, ActType
from src.signatures import generate_keypair, sign_record, SignatureAlgorithm
from src.hash_chain import compute_hash, GENESIS_HASH
from src.ledger import DecisionRecordLedger
from src.payment_ledger import PaymentLedger, PaymentRequest
from src.verify import PaymentVerifier


def main():
    print("=" * 60)
    print("Fides Protocol v0.3 - Basic Flow Demo")
    print("=" * 60)
    print()

    # Step 1: Generate key pair for the decider
    print("[1] Generating Ed25519 key pair for decider...")
    private_key, public_key = generate_keypair(SignatureAlgorithm.ED25519)
    print("    Key pair generated successfully.")
    print()

    # Step 2: Create a Decision Record
    print("[2] Creating Decision Record...")
    now = datetime.now(timezone.utc)

    dr = DecisionRecord(
        decision_id=uuid4(),
        authority_id="BR-GOV-DEMO-001",
        deciders_id=["CPF-12345678901"],
        act_type=ActType.CONTRACT,
        currency="BRL",
        maximum_value=Decimal("50000.00"),
        beneficiary="CNPJ-98765432000188",
        legal_basis="Lei 14.133/2021 Art. 75",
        decision_date=now - timedelta(minutes=15),
        previous_record_hash=GENESIS_HASH,
        record_timestamp=now,
        signatures=[],
    )

    print(f"    Decision ID: {dr.decision_id}")
    print(f"    Authority: {dr.authority_id}")
    print(f"    Act Type: {dr.act_type.value}")
    print(f"    Maximum Value: {dr.currency} {dr.maximum_value:,.2f}")
    print(f"    Beneficiary: {dr.beneficiary}")
    print()

    # Step 3: Sign the record
    print("[3] Signing the Decision Record...")
    signature = sign_record(
        dr,
        signer_id="CPF-12345678901",
        private_key=private_key,
        algorithm=SignatureAlgorithm.ED25519,
    )
    dr.signatures = [signature]
    print(f"    Signed at: {signature.signed_at}")
    print(f"    Algorithm: {signature.algorithm.value}")
    print()

    # Step 4: Validate the record
    print("[4] Validating the Decision Record...")
    is_valid, errors = dr.validate()
    if is_valid:
        print("    Validation: PASSED")
    else:
        print("    Validation: FAILED")
        for error in errors:
            print(f"      - {error}")
    print()

    # Step 5: Compute hash
    print("[5] Computing record hash...")
    record_hash = compute_hash(dr)
    print(f"    SHA-256: {record_hash}")
    print()

    # Step 6: Initialize ledgers
    print("[6] Initializing append-only ledgers...")
    dr_ledger = DecisionRecordLedger(":memory:")
    payment_ledger = PaymentLedger(":memory:")
    print("    Decision Record Ledger: initialized")
    print("    Payment Ledger: initialized")
    print()

    # Step 7: Append to ledger
    print("[7] Appending Decision Record to ledger...")
    stored_hash = dr_ledger.append_decision_record(dr)
    chain_state = dr_ledger.get_chain_state()
    print(f"    Stored hash: {stored_hash}")
    print(f"    Chain record count: {chain_state['record_count']}")
    print()

    # Step 8: Create payment verifier
    print("[8] Creating Payment Verifier...")
    verifier = PaymentVerifier(dr_ledger, payment_ledger, "EXECUTOR-DEMO-001")
    print("    Executor ID: EXECUTOR-DEMO-001")
    print()

    # Step 9: Execute first payment (should succeed)
    print("[9] Executing first payment (BRL 20,000.00)...")
    payment1 = PaymentRequest(
        decision_id=dr.decision_id,
        payment_amount=Decimal("20000.00"),
        payment_currency="BRL",
        payment_beneficiary="CNPJ-98765432000188",
        payment_date=datetime.now(timezone.utc),
    )

    success1, entry1 = verifier.execute_payment(dr.decision_id, payment1)
    if success1:
        print("    Result: AUTHORIZED")
        print(f"    Payment ID: {entry1.payment_id}")
    else:
        print(f"    Result: REJECTED ({entry1.rejection_reason.value})")
    print()

    # Step 10: Execute second payment (should succeed)
    print("[10] Executing second payment (BRL 25,000.00)...")
    payment2 = PaymentRequest(
        decision_id=dr.decision_id,
        payment_amount=Decimal("25000.00"),
        payment_currency="BRL",
        payment_beneficiary="CNPJ-98765432000188",
        payment_date=datetime.now(timezone.utc),
    )

    success2, entry2 = verifier.execute_payment(dr.decision_id, payment2)
    if success2:
        print("    Result: AUTHORIZED")
        print(f"    Payment ID: {entry2.payment_id}")
    else:
        print(f"    Result: REJECTED ({entry2.rejection_reason.value})")
    print()

    # Step 11: Check remaining balance
    print("[11] Checking remaining balance...")
    total_paid = payment_ledger.sum_authorized_payments(dr.decision_id)
    remaining = dr.maximum_value - total_paid
    print(f"    Total authorized: BRL {total_paid:,.2f}")
    print(f"    Maximum value: BRL {dr.maximum_value:,.2f}")
    print(f"    Remaining: BRL {remaining:,.2f}")
    print()

    # Step 12: Attempt payment that exceeds limit
    print("[12] Attempting payment that exceeds limit (BRL 10,000.00)...")
    payment3 = PaymentRequest(
        decision_id=dr.decision_id,
        payment_amount=Decimal("10000.00"),
        payment_currency="BRL",
        payment_beneficiary="CNPJ-98765432000188",
        payment_date=datetime.now(timezone.utc),
    )

    success3, entry3 = verifier.execute_payment(dr.decision_id, payment3)
    if success3:
        print("    Result: AUTHORIZED")
    else:
        print(f"    Result: REJECTED ({entry3.rejection_reason.value})")
        print("    This is correct behavior - payment would exceed maximum_value")
    print()

    # Step 13: Show all payments
    print("[13] Payment Ledger Summary...")
    all_payments = payment_ledger.get_payments_for_decision(dr.decision_id)
    print(f"    Total entries: {len(all_payments)}")
    for p in all_payments:
        status = "AUTHORIZED" if p.authorization_result else "REJECTED"
        print(f"    - {p.payment_id}: BRL {p.payment_amount:,.2f} [{status}]")
    print()

    print("=" * 60)
    print("Demo completed successfully!")
    print()
    print("Key principles demonstrated:")
    print("  - No payment without valid Decision Record")
    print("  - Cryptographic signatures for non-repudiation")
    print("  - Append-only ledger (immutability)")
    print("  - Cumulative payment tracking")
    print("  - Automatic rejection when maximum_value exceeded")
    print("=" * 60)


if __name__ == "__main__":
    main()
