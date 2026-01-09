"""
Fides Protocol v0.3 - Timestamp Attestation

Provides RFC 3161 timestamp attestation (stub implementation).
Production use requires integration with an external TSA.

Note: NTP consensus is DEPRECATED and REMOVED in v0.3 (Section 6.9.3).

SPDX-License-Identifier: AGPL-3.0-or-later
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .records import TimestampAttestation


@dataclass
class RFC3161Proof:
    """RFC 3161 timestamp proof structure (Section 6.9.1)."""
    tsa_url: str
    tsa_certificate: str  # base64 DER
    timestamp_token: str  # base64 DER
    hash_algorithm: str  # "SHA-256"
    message_imprint: str  # hex


@dataclass
class BlockchainProof:
    """Blockchain timestamp proof structure (Section 6.9.1)."""
    chain: str  # "bitcoin" | "ethereum"
    network: str  # "mainnet" | "testnet"
    block_number: int
    block_hash: str  # hex
    transaction_id: str  # hex
    merkle_proof: list[str]  # hex
    data_hash: str  # hex
    confirmations_at_record: int


class TimestampError(Exception):
    """Error during timestamp attestation."""
    pass


class RFC3161Client:
    """
    RFC 3161 Timestamp Authority client (stub).

    Production implementation should use rfc3161ng library
    and connect to an external TSA.
    """

    def __init__(self, tsa_url: str):
        """
        Initialize with TSA URL.

        TSA MUST be external to the implementing jurisdiction (Section 6.9).
        """
        self.tsa_url = tsa_url

    def get_timestamp(self, data_hash: bytes) -> TimestampAttestation:
        """
        Request a timestamp token from the TSA.

        This is a STUB implementation. Production code should:
        1. Create a TimeStampReq per RFC 3161
        2. Send to TSA via HTTP
        3. Parse TimeStampResp
        4. Verify the token
        5. Extract and return the proof

        See Section 6.9.2.1 for validation requirements.
        """
        # STUB: In production, this would contact the actual TSA
        raise NotImplementedError(
            "RFC 3161 client requires external TSA integration. "
            "See rfc3161ng library for implementation."
        )

    def verify_timestamp(
        self,
        attestation: TimestampAttestation,
        expected_hash: str,
    ) -> tuple[bool, Optional[str]]:
        """
        Verify an RFC 3161 timestamp attestation.

        Validation procedure (Section 6.9.2.1):
        1. Parse TimeStampToken
        2. Extract signer certificate
        3. Verify certificate chain
        4. Verify token signature
        5. Extract and verify message imprint
        6. Verify genTime is within acceptable range
        7. Verify TSA identity (external to jurisdiction)

        Returns (is_valid, error_message).
        """
        if attestation.method != "rfc3161":
            return False, "Not an RFC 3161 attestation"

        proof = attestation.proof

        # Verify message imprint matches expected hash
        if proof.get("message_imprint") != expected_hash:
            return False, "Message imprint does not match record hash"

        # STUB: Full validation requires:
        # - Parsing the DER-encoded timestamp_token
        # - Verifying certificate chain
        # - Checking certificate revocation (CRL/OCSP)
        # - Verifying EKU includes timeStamping
        # - Verifying token signature
        # - Checking genTime bounds

        raise NotImplementedError(
            "Full RFC 3161 validation requires cryptographic library support. "
            "See Section 6.9.2.1 for complete validation procedure."
        )


class BlockchainTimestamp:
    """
    Blockchain timestamp attestation (stub).

    Supports Bitcoin and Ethereum for timestamp anchoring.
    """

    def __init__(self, chain: str = "bitcoin", network: str = "mainnet"):
        """Initialize for the specified blockchain."""
        if chain not in ("bitcoin", "ethereum"):
            raise ValueError(f"Unsupported chain: {chain}")
        self.chain = chain
        self.network = network

    def anchor_hash(self, data_hash: bytes) -> TimestampAttestation:
        """
        Anchor a hash to the blockchain.

        This is a STUB. Production implementation should:
        1. Create a transaction with the hash in OP_RETURN (Bitcoin)
           or input data (Ethereum)
        2. Broadcast the transaction
        3. Wait for confirmations (6 for Bitcoin, 12 for Ethereum)
        4. Return the attestation with merkle proof

        See Section 6.9.1 for proof format.
        """
        raise NotImplementedError(
            "Blockchain anchoring requires external node/API integration."
        )

    def verify_anchor(
        self,
        attestation: TimestampAttestation,
        expected_hash: str,
    ) -> tuple[bool, Optional[str]]:
        """
        Verify a blockchain timestamp attestation.

        Validation procedure (Section 6.9.2.2):
        1. Verify block existence (2+ independent sources)
        2. Verify transaction inclusion via merkle proof
        3. Verify data_hash matches expected hash
        4. Verify minimum confirmations
        5. Verify block timestamp bounds

        Returns (is_valid, error_message).
        """
        if attestation.method != "blockchain":
            return False, "Not a blockchain attestation"

        proof = attestation.proof

        # Check chain matches
        if proof.get("chain") != self.chain:
            return False, f"Chain mismatch: expected {self.chain}"

        # Check data hash matches
        if proof.get("data_hash") != expected_hash:
            return False, "Data hash does not match record hash"

        # Check minimum confirmations
        min_confirmations = 6 if self.chain == "bitcoin" else 12
        if proof.get("confirmations_at_record", 0) < min_confirmations:
            return False, f"Insufficient confirmations (need {min_confirmations})"

        # STUB: Full validation requires:
        # - Querying block explorers / full nodes
        # - Verifying merkle proof
        # - Checking block timestamp bounds

        raise NotImplementedError(
            "Full blockchain validation requires node/API integration. "
            "See Section 6.9.2.2 for complete validation procedure."
        )


def create_rfc3161_attestation(
    tsa_url: str,
    record_hash: str,
    token: str,
    certificate: str,
) -> TimestampAttestation:
    """
    Create an RFC 3161 timestamp attestation object.

    Helper for constructing the attestation after receiving
    a response from an external TSA.
    """
    return TimestampAttestation(
        method="rfc3161",
        proof={
            "tsa_url": tsa_url,
            "tsa_certificate": certificate,
            "timestamp_token": token,
            "hash_algorithm": "SHA-256",
            "message_imprint": record_hash,
        },
        sources=[tsa_url],
    )


def create_blockchain_attestation(
    chain: str,
    network: str,
    block_number: int,
    block_hash: str,
    transaction_id: str,
    merkle_proof: list[str],
    data_hash: str,
    confirmations: int,
    explorer_urls: list[str],
) -> TimestampAttestation:
    """
    Create a blockchain timestamp attestation object.

    Helper for constructing the attestation after anchoring
    to a blockchain.
    """
    return TimestampAttestation(
        method="blockchain",
        proof={
            "chain": chain,
            "network": network,
            "block_number": block_number,
            "block_hash": block_hash,
            "transaction_id": transaction_id,
            "merkle_proof": merkle_proof,
            "data_hash": data_hash,
            "confirmations_at_record": confirmations,
        },
        sources=explorer_urls,
    )


def is_valid_attestation_method(method: str) -> bool:
    """
    Check if an attestation method is valid per v0.3.

    NTP consensus is DEPRECATED and REMOVED (Section 6.9.3).
    """
    valid_methods = {"rfc3161", "blockchain"}
    return method in valid_methods
