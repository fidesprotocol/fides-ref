"""
Fides Protocol v0.3 - Append-Only Decision Record Ledger

Implements an append-only SQLite ledger for Decision Records,
Special Decision Records, and Revocation Records.

Section 8.2: No UPDATE, No DELETE, No overwrite.

SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Optional, Union
from uuid import UUID

from .records import (
    DecisionRecord,
    SpecialDecisionRecord,
    RevocationRecord,
    ActType,
    ExceptionType,
    RevocationType,
    Signature,
    SignatureAlgorithm,
)
from .hash_chain import compute_hash, GENESIS_HASH, verify_chain_link


class LedgerError(Exception):
    """Base exception for ledger operations."""
    pass


class AppendOnlyViolation(LedgerError):
    """Raised when attempting to modify or delete records."""
    pass


class ChainBreakError(LedgerError):
    """Raised when a new record would break the hash chain."""
    pass


class DecisionRecordLedger:
    """
    Append-only ledger for Decision Records.

    Implements the structural requirements of Section 8.2:
    - Append-only mode
    - No UPDATE
    - No DELETE
    - No overwrite

    Uses SQLite with triggers to enforce immutability.
    """

    def __init__(self, db_path: Union[str, Path] = ":memory:"):
        """Initialize the ledger with the given database path."""
        self.db_path = str(db_path)
        self._local = threading.local()
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
        """Initialize the database schema with append-only constraints."""
        with self._conn:
            self._conn.executescript("""
                -- Decision Records table
                CREATE TABLE IF NOT EXISTS decision_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    decision_id TEXT UNIQUE NOT NULL,
                    authority_id TEXT NOT NULL,
                    deciders_id TEXT NOT NULL,  -- JSON array
                    act_type TEXT NOT NULL,
                    currency TEXT NOT NULL,
                    maximum_value REAL NOT NULL,
                    beneficiary TEXT NOT NULL,
                    legal_basis TEXT NOT NULL,
                    decision_date TEXT NOT NULL,
                    previous_record_hash TEXT NOT NULL,
                    record_timestamp TEXT NOT NULL,
                    signatures TEXT NOT NULL,  -- JSON array
                    timestamp_attestation TEXT,  -- JSON object
                    references_id TEXT,
                    program_id TEXT,
                    delay_justification TEXT,  -- JSON object
                    record_hash TEXT NOT NULL,
                    is_sdr INTEGER DEFAULT 0,
                    exception_type TEXT,
                    formal_justification TEXT,
                    maximum_term TEXT,
                    reinforced_deciders TEXT,  -- JSON array
                    oversight_authority TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                -- Revocation Records table
                CREATE TABLE IF NOT EXISTS revocation_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    revocation_id TEXT UNIQUE NOT NULL,
                    target_decision_id TEXT NOT NULL,
                    revocation_type TEXT NOT NULL,
                    revocation_reason TEXT NOT NULL,
                    revoker_authority TEXT NOT NULL,
                    revoker_id TEXT NOT NULL,  -- JSON array
                    revocation_date TEXT NOT NULL,
                    previous_record_hash TEXT NOT NULL,
                    record_timestamp TEXT NOT NULL,
                    signatures TEXT NOT NULL,  -- JSON array
                    timestamp_attestation TEXT,
                    org_chart_reference TEXT,  -- JSON object
                    record_hash TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                -- Chain state tracking
                CREATE TABLE IF NOT EXISTS chain_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    last_record_hash TEXT NOT NULL,
                    record_count INTEGER NOT NULL DEFAULT 0,
                    last_anchor_timestamp TEXT,
                    last_anchor_hash TEXT
                );

                -- Initialize chain state if not exists
                INSERT OR IGNORE INTO chain_state (id, last_record_hash, record_count)
                VALUES (1, '""" + GENESIS_HASH + """', 0);

                -- Trigger to prevent UPDATE on decision_records
                CREATE TRIGGER IF NOT EXISTS prevent_dr_update
                BEFORE UPDATE ON decision_records
                BEGIN
                    SELECT RAISE(ABORT, 'UPDATE not permitted on append-only ledger');
                END;

                -- Trigger to prevent DELETE on decision_records
                CREATE TRIGGER IF NOT EXISTS prevent_dr_delete
                BEFORE DELETE ON decision_records
                BEGIN
                    SELECT RAISE(ABORT, 'DELETE not permitted on append-only ledger');
                END;

                -- Trigger to prevent UPDATE on revocation_records
                CREATE TRIGGER IF NOT EXISTS prevent_rr_update
                BEFORE UPDATE ON revocation_records
                BEGIN
                    SELECT RAISE(ABORT, 'UPDATE not permitted on append-only ledger');
                END;

                -- Trigger to prevent DELETE on revocation_records
                CREATE TRIGGER IF NOT EXISTS prevent_rr_delete
                BEFORE DELETE ON revocation_records
                BEGIN
                    SELECT RAISE(ABORT, 'DELETE not permitted on append-only ledger');
                END;

                -- Indexes for efficient queries
                CREATE INDEX IF NOT EXISTS idx_dr_authority ON decision_records(authority_id);
                CREATE INDEX IF NOT EXISTS idx_dr_beneficiary ON decision_records(beneficiary);
                CREATE INDEX IF NOT EXISTS idx_dr_program ON decision_records(program_id);
                CREATE INDEX IF NOT EXISTS idx_dr_decision_date ON decision_records(decision_date);
                CREATE INDEX IF NOT EXISTS idx_rr_target ON revocation_records(target_decision_id);
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

    def _get_last_hash(self) -> str:
        """Get the hash of the last record in the chain."""
        cursor = self._conn.execute(
            "SELECT last_record_hash FROM chain_state WHERE id = 1"
        )
        row = cursor.fetchone()
        return row["last_record_hash"] if row else GENESIS_HASH

    def _get_record_count(self) -> int:
        """Get the total number of records in the chain."""
        cursor = self._conn.execute(
            "SELECT record_count FROM chain_state WHERE id = 1"
        )
        row = cursor.fetchone()
        return row["record_count"] if row else 0

    def append_decision_record(
        self,
        record: Union[DecisionRecord, SpecialDecisionRecord],
    ) -> str:
        """
        Append a Decision Record to the ledger.

        Validates the hash chain and returns the record's hash.
        Raises ChainBreakError if the record's previous_record_hash
        doesn't match the current chain head.
        """
        expected_hash = self._get_last_hash()

        if record.previous_record_hash != expected_hash:
            raise ChainBreakError(
                f"Chain break: expected {expected_hash}, "
                f"got {record.previous_record_hash}"
            )

        record_hash = compute_hash(record)

        is_sdr = isinstance(record, SpecialDecisionRecord)

        with self._transaction():
            self._conn.execute(
                """
                INSERT INTO decision_records (
                    decision_id, authority_id, deciders_id, act_type,
                    currency, maximum_value, beneficiary, legal_basis,
                    decision_date, previous_record_hash, record_timestamp,
                    signatures, timestamp_attestation, references_id,
                    program_id, delay_justification, record_hash,
                    is_sdr, exception_type, formal_justification,
                    maximum_term, reinforced_deciders, oversight_authority
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(record.decision_id),
                    record.authority_id,
                    json.dumps(record.deciders_id),
                    record.act_type.value,
                    record.currency,
                    float(record.maximum_value),
                    record.beneficiary,
                    record.legal_basis,
                    record.decision_date.isoformat(),
                    record.previous_record_hash,
                    record.record_timestamp.isoformat(),
                    json.dumps([self._signature_to_dict(s) for s in record.signatures]),
                    json.dumps(asdict(record.timestamp_attestation)) if record.timestamp_attestation else None,
                    str(record.references) if record.references else None,
                    record.program_id,
                    json.dumps(asdict(record.delay_justification)) if record.delay_justification else None,
                    record_hash,
                    1 if is_sdr else 0,
                    record.exception_type.value if is_sdr and record.exception_type else None,
                    record.formal_justification if is_sdr else None,
                    record.maximum_term.isoformat() if is_sdr and record.maximum_term else None,
                    json.dumps(record.reinforced_deciders) if is_sdr else None,
                    record.oversight_authority if is_sdr else None,
                ),
            )

            # Update chain state
            self._conn.execute(
                """
                UPDATE chain_state
                SET last_record_hash = ?, record_count = record_count + 1
                WHERE id = 1
                """,
                (record_hash,),
            )

        return record_hash

    def append_revocation_record(self, record: RevocationRecord) -> str:
        """
        Append a Revocation Record to the ledger.

        Validates the hash chain and returns the record's hash.
        """
        expected_hash = self._get_last_hash()

        if record.previous_record_hash != expected_hash:
            raise ChainBreakError(
                f"Chain break: expected {expected_hash}, "
                f"got {record.previous_record_hash}"
            )

        record_hash = compute_hash(record)

        with self._transaction():
            self._conn.execute(
                """
                INSERT INTO revocation_records (
                    revocation_id, target_decision_id, revocation_type,
                    revocation_reason, revoker_authority, revoker_id,
                    revocation_date, previous_record_hash, record_timestamp,
                    signatures, timestamp_attestation, org_chart_reference,
                    record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(record.revocation_id),
                    str(record.target_decision_id),
                    record.revocation_type.value,
                    record.revocation_reason,
                    record.revoker_authority,
                    json.dumps(record.revoker_id),
                    record.revocation_date.isoformat(),
                    record.previous_record_hash,
                    record.record_timestamp.isoformat(),
                    json.dumps([self._signature_to_dict(s) for s in record.signatures]),
                    json.dumps(asdict(record.timestamp_attestation)) if record.timestamp_attestation else None,
                    json.dumps(record.org_chart_reference) if record.org_chart_reference else None,
                    record_hash,
                ),
            )

            # Update chain state
            self._conn.execute(
                """
                UPDATE chain_state
                SET last_record_hash = ?, record_count = record_count + 1
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

    def get_decision_record(self, decision_id: UUID) -> Optional[DecisionRecord]:
        """Retrieve a Decision Record by its ID."""
        cursor = self._conn.execute(
            "SELECT * FROM decision_records WHERE decision_id = ?",
            (str(decision_id),),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_decision_record(row)

    def is_revoked(self, decision_id: UUID) -> bool:
        """Check if a Decision Record has been revoked."""
        cursor = self._conn.execute(
            "SELECT 1 FROM revocation_records WHERE target_decision_id = ?",
            (str(decision_id),),
        )
        return cursor.fetchone() is not None

    def get_revocation(self, decision_id: UUID) -> Optional[RevocationRecord]:
        """Get the revocation record for a decision, if any."""
        cursor = self._conn.execute(
            "SELECT * FROM revocation_records WHERE target_decision_id = ?",
            (str(decision_id),),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_revocation_record(row)

    def get_chain_state(self) -> dict:
        """Get current chain state for external anchoring."""
        cursor = self._conn.execute(
            "SELECT * FROM chain_state WHERE id = 1"
        )
        row = cursor.fetchone()
        return {
            "last_record_hash": row["last_record_hash"],
            "record_count": row["record_count"],
            "last_anchor_timestamp": row["last_anchor_timestamp"],
            "last_anchor_hash": row["last_anchor_hash"],
        }

    def record_anchor(self, anchor_hash: str, timestamp: datetime):
        """Record that an external anchor was published."""
        # This is a metadata update, not a record modification
        self._conn.execute(
            """
            UPDATE chain_state
            SET last_anchor_timestamp = ?, last_anchor_hash = ?
            WHERE id = 1
            """,
            (timestamp.isoformat(), anchor_hash),
        )
        self._conn.commit()

    def _row_to_decision_record(self, row) -> Union[DecisionRecord, SpecialDecisionRecord]:
        """Convert a database row to a DecisionRecord or SDR."""
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

        base_kwargs = {
            "decision_id": UUID(row["decision_id"]),
            "authority_id": row["authority_id"],
            "deciders_id": json.loads(row["deciders_id"]),
            "act_type": ActType(row["act_type"]),
            "currency": row["currency"],
            "maximum_value": row["maximum_value"],
            "beneficiary": row["beneficiary"],
            "legal_basis": row["legal_basis"],
            "decision_date": datetime.fromisoformat(row["decision_date"]),
            "previous_record_hash": row["previous_record_hash"],
            "record_timestamp": datetime.fromisoformat(row["record_timestamp"]),
            "signatures": signatures,
            "references": UUID(row["references_id"]) if row["references_id"] else None,
            "program_id": row["program_id"],
        }

        if row["is_sdr"]:
            return SpecialDecisionRecord(
                **base_kwargs,
                is_sdr=True,
                exception_type=ExceptionType(row["exception_type"]) if row["exception_type"] else None,
                formal_justification=row["formal_justification"],
                maximum_term=datetime.fromisoformat(row["maximum_term"]) if row["maximum_term"] else None,
                reinforced_deciders=json.loads(row["reinforced_deciders"]) if row["reinforced_deciders"] else [],
                oversight_authority=row["oversight_authority"],
            )

        return DecisionRecord(**base_kwargs)

    def _row_to_revocation_record(self, row) -> RevocationRecord:
        """Convert a database row to a RevocationRecord."""
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

        return RevocationRecord(
            revocation_id=UUID(row["revocation_id"]),
            target_decision_id=UUID(row["target_decision_id"]),
            revocation_type=RevocationType(row["revocation_type"]),
            revocation_reason=row["revocation_reason"],
            revoker_authority=row["revoker_authority"],
            revoker_id=json.loads(row["revoker_id"]),
            revocation_date=datetime.fromisoformat(row["revocation_date"]),
            previous_record_hash=row["previous_record_hash"],
            record_timestamp=datetime.fromisoformat(row["record_timestamp"]),
            signatures=signatures,
            org_chart_reference=json.loads(row["org_chart_reference"]) if row["org_chart_reference"] else None,
        )
