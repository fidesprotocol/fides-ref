"""
Fides Protocol v0.3 - Hash Chain and Canonical Serialization

Implements SHA-256 hash chaining and canonical JSON serialization
as defined in Section 6.6.

SPDX-License-Identifier: AGPL-3.0-or-later
"""

import hashlib
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Union
from uuid import UUID


# Genesis hash for the first record in the chain
GENESIS_HASH = "0" * 64


def _serialize_value(value: Any) -> Any:
    """
    Convert a value to JSON-serializable format following canonical rules.

    Rules (Section 6.6.1):
    - Dates in ISO 8601 format with UTC timezone (Z suffix)
    - Numbers without unnecessary precision
    - UUIDs as strings
    - Enums as their value
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        # ISO 8601 with UTC timezone (Z suffix)
        if value.tzinfo is None:
            raise ValueError("Datetime must be timezone-aware for canonical serialization")
        # Format with Z suffix for UTC
        utc_dt = value.astimezone(tz=None)  # Convert to UTC
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    if isinstance(value, UUID):
        return str(value)

    if isinstance(value, Decimal):
        # No trailing zeros, but maintain precision for currency
        # Convert to float for JSON, ensuring no unnecessary precision
        return float(value)

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, (list, tuple)):
        return [_serialize_value(item) for item in value]

    if isinstance(value, dict):
        return {k: _serialize_value(v) for k, v in value.items()}

    if is_dataclass(value) and not isinstance(value, type):
        return _serialize_value(asdict(value))

    return value


def _sort_keys_recursive(obj: Any) -> Any:
    """Recursively sort dictionary keys alphabetically."""
    if isinstance(obj, dict):
        return {k: _sort_keys_recursive(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_sort_keys_recursive(item) for item in obj]
    return obj


def canonical_serialize(record: Any) -> bytes:
    """
    Serialize a record to canonical JSON bytes.

    Canonical format (Section 6.6.1):
    1. JSON format
    2. UTF-8 encoding
    3. Keys sorted alphabetically (recursive)
    4. No whitespace between elements
    5. No trailing newline
    6. Numbers without unnecessary precision
    7. Dates in ISO 8601 format with UTC timezone (Z suffix)
    """
    # Convert to dictionary if dataclass
    if is_dataclass(record) and not isinstance(record, type):
        obj = asdict(record)
    elif isinstance(record, dict):
        obj = record.copy()
    else:
        raise TypeError(f"Cannot serialize {type(record)}")

    # Remove computed fields that should not be part of the hash
    # (the hash itself, if present)
    obj.pop("hash", None)
    obj.pop("computed_fields", None)

    # Convert values to serializable format
    obj = _serialize_value(obj)

    # Sort keys recursively
    obj = _sort_keys_recursive(obj)

    # Serialize to JSON with no whitespace
    json_str = json.dumps(
        obj,
        separators=(",", ":"),
        ensure_ascii=False,
        sort_keys=True,
    )

    # Encode as UTF-8
    return json_str.encode("utf-8")


def compute_hash(record: Any) -> str:
    """
    Compute the SHA-256 hash of a record's canonical serialization.

    Returns the hash as a lowercase hexadecimal string.
    """
    canonical_bytes = canonical_serialize(record)
    return hashlib.sha256(canonical_bytes).hexdigest()


def verify_chain_link(current_record: Any, previous_record: Any) -> bool:
    """
    Verify that current_record correctly chains to previous_record.

    The current record's previous_record_hash must match
    the computed hash of the previous record.
    """
    expected_hash = compute_hash(previous_record)
    actual_hash = getattr(current_record, "previous_record_hash", None)

    if actual_hash is None:
        return False

    return actual_hash == expected_hash


def verify_chain(records: list) -> tuple[bool, int, str]:
    """
    Verify the integrity of an entire hash chain.

    Returns (is_valid, break_index, error_message).
    If valid, break_index is -1.
    If invalid, break_index is the index of the first broken link.
    """
    if not records:
        return True, -1, ""

    # First record should chain to genesis
    first = records[0]
    if getattr(first, "previous_record_hash", None) != GENESIS_HASH:
        return False, 0, "First record does not chain to genesis hash"

    # Verify each subsequent link
    for i in range(1, len(records)):
        if not verify_chain_link(records[i], records[i - 1]):
            expected = compute_hash(records[i - 1])
            actual = getattr(records[i], "previous_record_hash", "MISSING")
            return False, i, f"Chain break at index {i}: expected {expected}, got {actual}"

    return True, -1, ""


def compute_state_hash(records: list) -> str:
    """
    Compute the state hash for external anchoring.

    The state hash is the SHA-256 of the concatenation of all record hashes.
    This allows verification that no records have been altered or removed.
    """
    if not records:
        return GENESIS_HASH

    hasher = hashlib.sha256()
    for record in records:
        record_hash = compute_hash(record)
        hasher.update(record_hash.encode("utf-8"))

    return hasher.hexdigest()


class ChainIntegrityError(Exception):
    """Raised when hash chain integrity is violated."""

    def __init__(self, message: str, break_index: int = -1):
        super().__init__(message)
        self.break_index = break_index
