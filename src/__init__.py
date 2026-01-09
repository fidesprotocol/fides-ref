"""
Fides Protocol v0.3 - Reference Implementation

This package provides a complete reference implementation of the Fides Protocol,
demonstrating all v0.3 requirements including:

- Decision Records (DR) with cryptographic signatures
- Special Decision Records (SDR) for typed exceptions
- Revocation Records (RR)
- SHA-256 hash chaining
- Ed25519 signatures
- RFC 3161 timestamp attestation (stub)
- Append-only ledger
- Payment authorization verification

SPDX-License-Identifier: AGPL-3.0-or-later
"""

__version__ = "0.3.0"
__protocol_version__ = "0.3"

from .records import DecisionRecord, SpecialDecisionRecord, RevocationRecord
from .signatures import sign_record, verify_signature, generate_keypair
from .hash_chain import canonical_serialize, compute_hash
from .verify import is_payment_authorized

__all__ = [
    "DecisionRecord",
    "SpecialDecisionRecord",
    "RevocationRecord",
    "sign_record",
    "verify_signature",
    "generate_keypair",
    "canonical_serialize",
    "compute_hash",
    "is_payment_authorized",
]
