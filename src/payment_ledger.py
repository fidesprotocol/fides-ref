"""
Fides Protocol v0.3 - Payment Ledger

Implements the append-only payment ledger as defined in Section 7.7.
Records ALL payment authorization requests, whether authorized or rejected.

SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Optional, Union
from uuid import UUID, uuid4

from .records import Signature, SignatureAlgorithm
from .hash_chain import compute_hash, GENESIS_HASH


class RejectionReason(str, Enum):
    """Rejection reason codes (Appendix H)."""
    DR_NOT_FOUND = "DR_NOT_FOUND"
    DR_REVOKED = "DR_REVOKED"
    DR_INVALID = "DR_INVALID"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    TIMESTAMP_INVALID = "TIMESTAMP_INVALID"
    PAYMENT_BEFORE_DECISION = "PAYMENT_BEFORE_DECISION"
    BENEFICIARY_MISMATCH = "BENEFICIARY_MISMATCH"
    CURRENCY_MISMATCH = "CURRENCY_MISMATCH"
    SDR_EXPIRED = "SDR_EXPIRED"
    MAXIMUM_VALUE_EXCEEDED = "MAXIMUM_VALUE_EXCEEDED"
    EXECUTOR_UNAVAILABLE = "EXECUTOR_UNAVAILABLE"
    CHAIN_INTEGRITY_FAILURE = "CHAIN_INTEGRITY_FAILURE"
    ATTESTATION_SUSPECT = "ATTESTATION_SUSPECT"
    BANK_EXECUTION_FAILED = "BANK_EXECUTION_FAILED"


@dataclass
class PaymentRequest:
    """A payment authorization request."""
    decision_id: UUID
    payment_amount: Decimal
    payment_currency: str  # ISO 4217
    payment_beneficiary: str
    payment_date: datetime


@dataclass
class PaymentLedgerEntry:
    """
    Payment Ledger Entry (Section 7.7.1).

    Records payment authorization requests and their outcomes.
    """
    payment_id: UUID
    decision_id: UUID
    payment_amount: Decimal
    payment_currency: str
    payment_beneficiary: str
    request_timestamp: datetime
    authorization_result: bool
    rejection_reason: Optional[RejectionReason]
    execution_timestamp: Optional[datetime]
    payment_executor_id: str
    previous_payment_hash: str
    signatures: list[Signature]
    timestamp_attestation: Optional[dict] = None

    @classmethod
    def create_authorized(
        cls,
        decision_id: UUID,
        payment_amount: Decimal,
        payment_currency: str,
        payment_beneficiary: str,
        payment_executor_id: str,
        previous_payment_hash: str,
    ) -> "PaymentLedgerEntry":
        """Create an authorized payment entry."""
        now = datetime.now(timezone.utc)
        return cls(
            payment_id=uuid4(),
            decision_id=decision_id,
            payment_amount=payment_amount,
            payment_currency=payment_currency,
            payment_beneficiary=payment_beneficiary,
            request_timestamp=now,
            authorization_result=True,
            rejection_reason=None,
            execution_timestamp=now,
            payment_executor_id=payment_executor_id,
            previous_payment_hash=previous_payment_hash,
            signatures=[],
        )

    @classmethod
    def create_rejected(
        cls,
        decision_id: UUID,
        payment_amount: Decimal,
        payment_currency: str,
        payment_beneficiary: str,
        payment_executor_id: str,
        previous_payment_hash: str,
        rejection_reason: RejectionReason,
    ) -> "PaymentLedgerEntry":
        """Create a rejected payment entry."""
        now = datetime.now(timezone.utc)
        return cls(
            payment_id=uuid4(),
            decision_id=decision_id,
            payment_amount=payment_amount,
            payment_currency=payment_currency,
            payment_beneficiary=payment_beneficiary,
            request_timestamp=now,
            authorization_result=False,
            rejection_reason=rejection_reason,
            execution_timestamp=None,
            payment_executor_id=payment_executor_id,
            previous_payment_hash=previous_payment_hash,
            signatures=[],
        )


class PaymentLedger:
    """
    Append-only Payment Ledger (Section 7.7).

    Requirements:
    - Append-only: No UPDATE or DELETE
    - Chained: Each entry includes hash of previous
    - Complete: Both authorized AND rejected recorded
    - Public: Accessible without authentication
    - Machine-readable: JSON format
    - Timestamped: External attestation required
    """

    def __init__(self, db_path: Union[str, Path] = ":memory:"):
        """Initialize the payment ledger."""
        self.db_path = str(db_path)
        self._local = threading.local()
        self._locks: dict[str, threading.Lock] = {}
        self._global_lock = threading.Lock()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
            )
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        """Initialize the payment ledger schema."""
        with self._conn:
            self._conn.executescript("""
                -- Payment Ledger entries
                CREATE TABLE IF NOT EXISTS payment_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payment_id TEXT UNIQUE NOT NULL,
                    decision_id TEXT NOT NULL,
                    payment_amount REAL NOT NULL,
                    payment_currency TEXT NOT NULL,
                    payment_beneficiary TEXT NOT NULL,
                    request_timestamp TEXT NOT NULL,
                    authorization_result INTEGER NOT NULL,
                    rejection_reason TEXT,
                    execution_timestamp TEXT,
                    payment_executor_id TEXT NOT NULL,
                    previous_payment_hash TEXT NOT NULL,
                    signatures TEXT NOT NULL,
                    timestamp_attestation TEXT,
                    record_hash TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                -- Chain state for payment ledger
                CREATE TABLE IF NOT EXISTS payment_chain_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    last_payment_hash TEXT NOT NULL,
                    payment_count INTEGER NOT NULL DEFAULT 0
                );

                -- Initialize if not exists
                INSERT OR IGNORE INTO payment_chain_state (id, last_payment_hash, payment_count)
                VALUES (1, '""" + GENESIS_HASH + """', 0);

                -- Prevent UPDATE
                CREATE TRIGGER IF NOT EXISTS prevent_payment_update
                BEFORE UPDATE ON payment_entries
                BEGIN
                    SELECT RAISE(ABORT, 'UPDATE not permitted on payment ledger');
                END;

                -- Prevent DELETE
                CREATE TRIGGER IF NOT EXISTS prevent_payment_delete
                BEFORE DELETE ON payment_entries
                BEGIN
                    SELECT RAISE(ABORT, 'DELETE not permitted on payment ledger');
                END;

                -- Indexes
                CREATE INDEX IF NOT EXISTS idx_payment_decision ON payment_entries(decision_id);
                CREATE INDEX IF NOT EXISTS idx_payment_beneficiary ON payment_entries(payment_beneficiary);
                CREATE INDEX IF NOT EXISTS idx_payment_authorized ON payment_entries(authorization_result);
            """)

    @contextmanager
    def _transaction(self):
        """Context manager for database transactions."""
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def acquire_lock(self, decision_id: UUID) -> threading.Lock:
        """
        Acquire exclusive lock for a decision_id (Section 7.6).

        Payments against the same decision_id MUST be processed serially.
        """
        key = str(decision_id)
        with self._global_lock:
            if key not in self._locks:
                self._locks[key] = threading.Lock()
            lock = self._locks[key]
        lock.acquire()
        return lock

    def release_lock(self, lock: threading.Lock):
        """Release a previously acquired lock."""
        lock.release()

    def get_last_payment_hash(self) -> str:
        """Get the hash of the last payment entry."""
        cursor = self._conn.execute(
            "SELECT last_payment_hash FROM payment_chain_state WHERE id = 1"
        )
        row = cursor.fetchone()
        return row["last_payment_hash"] if row else GENESIS_HASH

    def record_payment(self, entry: PaymentLedgerEntry) -> str:
        """
        Record a payment entry to the ledger.

        Returns the entry's hash.
        """
        record_hash = compute_hash(entry)

        with self._transaction():
            self._conn.execute(
                """
                INSERT INTO payment_entries (
                    payment_id, decision_id, payment_amount, payment_currency,
                    payment_beneficiary, request_timestamp, authorization_result,
                    rejection_reason, execution_timestamp, payment_executor_id,
                    previous_payment_hash, signatures, timestamp_attestation,
                    record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(entry.payment_id),
                    str(entry.decision_id),
                    float(entry.payment_amount),
                    entry.payment_currency,
                    entry.payment_beneficiary,
                    entry.request_timestamp.isoformat(),
                    1 if entry.authorization_result else 0,
                    entry.rejection_reason.value if entry.rejection_reason else None,
                    entry.execution_timestamp.isoformat() if entry.execution_timestamp else None,
                    entry.payment_executor_id,
                    entry.previous_payment_hash,
                    json.dumps([self._signature_to_dict(s) for s in entry.signatures]),
                    json.dumps(entry.timestamp_attestation) if entry.timestamp_attestation else None,
                    record_hash,
                ),
            )

            # Update chain state
            self._conn.execute(
                """
                UPDATE payment_chain_state
                SET last_payment_hash = ?, payment_count = payment_count + 1
                WHERE id = 1
                """,
                (record_hash,),
            )

        return record_hash

    def _signature_to_dict(self, sig: Signature) -> dict:
        """Convert a Signature to a dictionary."""
        return {
            "signer_id": sig.signer_id,
            "public_key": sig.public_key,
            "algorithm": sig.algorithm.value,
            "signature": sig.signature,
            "signed_at": sig.signed_at.isoformat(),
        }

    def sum_authorized_payments(self, decision_id: UUID) -> Decimal:
        """
        Sum all authorized payments for a decision_id.

        This is critical for the maximum_value check.
        """
        cursor = self._conn.execute(
            """
            SELECT COALESCE(SUM(payment_amount), 0) as total
            FROM payment_entries
            WHERE decision_id = ? AND authorization_result = 1
            """,
            (str(decision_id),),
        )
        row = cursor.fetchone()
        return Decimal(str(row["total"]))

    def get_payments_for_decision(self, decision_id: UUID) -> list[PaymentLedgerEntry]:
        """Get all payment entries (authorized and rejected) for a decision."""
        cursor = self._conn.execute(
            "SELECT * FROM payment_entries WHERE decision_id = ? ORDER BY id",
            (str(decision_id),),
        )
        return [self._row_to_entry(row) for row in cursor.fetchall()]

    def get_rejected_payments(self) -> list[PaymentLedgerEntry]:
        """Get all rejected payments (Section 7.7.3)."""
        cursor = self._conn.execute(
            "SELECT * FROM payment_entries WHERE authorization_result = 0 ORDER BY id"
        )
        return [self._row_to_entry(row) for row in cursor.fetchall()]

    def _row_to_entry(self, row) -> PaymentLedgerEntry:
        """Convert a database row to a PaymentLedgerEntry."""
        signatures = [
            Signature(
                signer_id=s["signer_id"],
                public_key=s["public_key"],
                algorithm=SignatureAlgorithm(s["algorithm"]),
                signature=s["signature"],
                signed_at=datetime.fromisoformat(s["signed_at"]),
            )
            for s in json.loads(row["signatures"])
        ]

        return PaymentLedgerEntry(
            payment_id=UUID(row["payment_id"]),
            decision_id=UUID(row["decision_id"]),
            payment_amount=Decimal(str(row["payment_amount"])),
            payment_currency=row["payment_currency"],
            payment_beneficiary=row["payment_beneficiary"],
            request_timestamp=datetime.fromisoformat(row["request_timestamp"]),
            authorization_result=bool(row["authorization_result"]),
            rejection_reason=RejectionReason(row["rejection_reason"]) if row["rejection_reason"] else None,
            execution_timestamp=datetime.fromisoformat(row["execution_timestamp"]) if row["execution_timestamp"] else None,
            payment_executor_id=row["payment_executor_id"],
            previous_payment_hash=row["previous_payment_hash"],
            signatures=signatures,
            timestamp_attestation=json.loads(row["timestamp_attestation"]) if row["timestamp_attestation"] else None,
        )

    def reconcile_with_dr(self, decision_id: UUID, dr_maximum_value: Decimal) -> dict:
        """
        Reconciliation check (Section 7.7.4).

        For a decision_id: sum(authorized_payments) <= dr.maximum_value
        """
        total_authorized = self.sum_authorized_payments(decision_id)

        return {
            "decision_id": str(decision_id),
            "total_authorized": float(total_authorized),
            "maximum_value": float(dr_maximum_value),
            "within_limit": total_authorized <= dr_maximum_value,
            "remaining": float(dr_maximum_value - total_authorized),
        }
