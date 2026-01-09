"""
Tests for hash chain and canonical serialization.

SPDX-License-Identifier: AGPL-3.0-or-later
"""

import pytest
from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID

from src.hash_chain import (
    canonical_serialize,
    compute_hash,
    verify_chain_link,
    verify_chain,
    compute_state_hash,
    GENESIS_HASH,
)
from src.records import DecisionRecord, ActType, Signature, SignatureAlgorithm


class TestCanonicalSerialization:
    """Tests for canonical JSON serialization (Section 6.6.1)."""

    def test_keys_sorted_alphabetically(self):
        """Test that keys are sorted alphabetically."""
        obj = {"zebra": 1, "apple": 2, "mango": 3}
        result = canonical_serialize(obj).decode("utf-8")
        # Keys should appear in order: apple, mango, zebra
        assert result.index("apple") < result.index("mango")
        assert result.index("mango") < result.index("zebra")

    def test_no_whitespace(self):
        """Test that there's no whitespace between elements."""
        obj = {"a": 1, "b": 2}
        result = canonical_serialize(obj).decode("utf-8")
        assert " " not in result
        assert "\n" not in result

    def test_datetime_format(self):
        """Test datetime is formatted as ISO 8601 with Z suffix."""
        dt = datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        obj = {"date": dt}
        result = canonical_serialize(obj).decode("utf-8")
        assert "2025-01-15T10:00:00Z" in result

    def test_uuid_as_string(self):
        """Test UUID is serialized as string."""
        uuid = UUID("550e8400-e29b-41d4-a716-446655440000")
        obj = {"id": uuid}
        result = canonical_serialize(obj).decode("utf-8")
        assert "550e8400-e29b-41d4-a716-446655440000" in result

    def test_decimal_no_trailing_zeros(self):
        """Test Decimal is serialized without trailing zeros."""
        obj = {"value": Decimal("10000.00")}
        result = canonical_serialize(obj).decode("utf-8")
        # Should be serialized as float
        assert "10000" in result

    def test_nested_objects_sorted(self):
        """Test that nested objects also have sorted keys."""
        obj = {"outer": {"z": 1, "a": 2}}
        result = canonical_serialize(obj).decode("utf-8")
        z_pos = result.index('"z"')
        a_pos = result.index('"a"')
        assert a_pos < z_pos

    def test_deterministic_output(self):
        """Test that same input always produces same output."""
        obj = {"a": 1, "b": [1, 2, 3], "c": {"x": "y"}}
        result1 = canonical_serialize(obj)
        result2 = canonical_serialize(obj)
        assert result1 == result2


class TestComputeHash:
    """Tests for SHA-256 hash computation."""

    def test_hash_is_hex_string(self):
        """Test that hash is returned as hex string."""
        obj = {"test": "data"}
        hash_result = compute_hash(obj)
        assert len(hash_result) == 64
        assert all(c in "0123456789abcdef" for c in hash_result)

    def test_hash_is_deterministic(self):
        """Test that same input always produces same hash."""
        obj = {"test": "data"}
        hash1 = compute_hash(obj)
        hash2 = compute_hash(obj)
        assert hash1 == hash2

    def test_different_inputs_different_hashes(self):
        """Test that different inputs produce different hashes."""
        hash1 = compute_hash({"a": 1})
        hash2 = compute_hash({"a": 2})
        assert hash1 != hash2


class TestChainVerification:
    """Tests for hash chain verification."""

    def test_verify_chain_link_valid(self):
        """Test chain link verification with valid link."""
        prev_record = {
            "decision_id": "550e8400-e29b-41d4-a716-446655440000",
            "previous_record_hash": GENESIS_HASH,
            "data": "test",
        }
        prev_hash = compute_hash(prev_record)

        class CurrentRecord:
            def __init__(self):
                self.previous_record_hash = prev_hash

        current_record = CurrentRecord()
        assert verify_chain_link(current_record, prev_record)

    def test_verify_chain_link_invalid(self):
        """Test chain link verification with broken link."""
        prev_record = {"data": "test"}

        class CurrentRecord:
            def __init__(self):
                self.previous_record_hash = "wrong_hash"

        current_record = CurrentRecord()
        assert not verify_chain_link(current_record, prev_record)

    def test_verify_empty_chain(self):
        """Test verification of empty chain."""
        is_valid, break_index, error = verify_chain([])
        assert is_valid
        assert break_index == -1

    def test_compute_state_hash_empty(self):
        """Test state hash of empty chain is genesis hash."""
        assert compute_state_hash([]) == GENESIS_HASH

    def test_compute_state_hash_deterministic(self):
        """Test state hash is deterministic."""
        records = [{"data": "a"}, {"data": "b"}]
        hash1 = compute_state_hash(records)
        hash2 = compute_state_hash(records)
        assert hash1 == hash2
