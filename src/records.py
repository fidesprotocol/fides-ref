"""
Fides Protocol v0.3 - Record Types

Implements Decision Record (DR), Special Decision Record (SDR),
and Revocation Record (RR) as defined in the protocol specification.

SPDX-License-Identifier: AGPL-3.0-or-later
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4


class ActType(str, Enum):
    """Mandatory taxonomy of administrative act types (Section 6.3.1)."""
    COMMITMENT = "commitment"
    CONTRACT = "contract"
    AMENDMENT = "amendment"
    PURCHASE_ORDER = "purchase_order"
    GRANT = "grant"
    PAYROLL = "payroll"
    REIMBURSEMENT = "reimbursement"
    TRANSFER = "transfer"


class ExceptionType(str, Enum):
    """Permitted exception types for SDR (Section 9.3)."""
    PUBLIC_CALAMITY = "public_calamity"
    COURT_ORDER = "court_order"
    HEALTH_EMERGENCY = "health_emergency"
    ESSENTIAL_SERVICE = "essential_service"
    NATIONAL_SECURITY = "national_security"
    LATE_REGISTRATION = "late_registration"


class RevocationType(str, Enum):
    """Types of revocation (Section 10.3)."""
    VOLUNTARY = "voluntary"
    OVERSIGHT = "oversight"
    JUDICIAL = "judicial"
    SUPERSEDED = "superseded"


class SignatureAlgorithm(str, Enum):
    """Acceptable signature algorithms (Section 6.3.2)."""
    ED25519 = "Ed25519"
    ECDSA_P256 = "ECDSA-P256"
    ECDSA_P384 = "ECDSA-P384"
    RSA_PSS = "RSA-PSS"


class DelayReason(str, Enum):
    """Delay reasons for registration > 1 hour (Section 6.4.5)."""
    SYSTEM_OUTAGE = "system_outage"
    WEEKEND_CLOSURE = "weekend_closure"
    HOLIDAY = "holiday"
    MANUAL_PROCESSING = "manual_processing"
    OTHER = "other"


@dataclass
class Signature:
    """Cryptographic signature structure (Section 6.3.2)."""
    signer_id: str
    public_key: str  # base64 encoded
    algorithm: SignatureAlgorithm
    signature: str  # base64 encoded
    signed_at: datetime


@dataclass
class TimestampAttestation:
    """Timestamp attestation proof (Section 6.9.1)."""
    method: str  # "rfc3161" or "blockchain"
    proof: dict
    sources: list[str] = field(default_factory=list)


@dataclass
class DelayJustification:
    """Justification for delayed registration (Section 6.4.5)."""
    delay_hours: float
    delay_reason: DelayReason
    delay_explanation: Optional[str] = None
    supervisor_approval: Optional[dict] = None


@dataclass
class DecisionRecord:
    """
    Decision Record (DR) - Section 6

    The technical artifact that potentially authorizes the future
    execution of a public expenditure.
    """
    decision_id: UUID
    authority_id: str
    deciders_id: list[str]
    act_type: ActType
    currency: str  # ISO 4217
    maximum_value: Decimal
    beneficiary: str
    legal_basis: str
    decision_date: datetime
    previous_record_hash: str  # SHA-256 hex
    record_timestamp: datetime
    signatures: list[Signature]
    timestamp_attestation: Optional[TimestampAttestation] = None
    references: Optional[UUID] = None  # For amendments
    program_id: Optional[str] = None  # For audit correlation
    delay_justification: Optional[DelayJustification] = None

    @classmethod
    def create(
        cls,
        authority_id: str,
        deciders_id: list[str],
        act_type: ActType,
        currency: str,
        maximum_value: Decimal,
        beneficiary: str,
        legal_basis: str,
        decision_date: datetime,
        previous_record_hash: str,
        **kwargs
    ) -> "DecisionRecord":
        """Factory method to create a new Decision Record."""
        return cls(
            decision_id=uuid4(),
            authority_id=authority_id,
            deciders_id=deciders_id,
            act_type=act_type,
            currency=currency,
            maximum_value=maximum_value,
            beneficiary=beneficiary,
            legal_basis=legal_basis,
            decision_date=decision_date,
            previous_record_hash=previous_record_hash,
            record_timestamp=datetime.now(timezone.utc),
            signatures=[],
            **kwargs
        )

    def validate(self) -> tuple[bool, list[str]]:
        """
        Validate the Decision Record against protocol rules (Section 6.4).
        Returns (is_valid, list_of_errors).
        """
        errors = []

        # Rule 1: All required fields present (checked by dataclass)

        # Rule 2: maximum_value > 0
        if self.maximum_value <= 0:
            errors.append("maximum_value must be positive")

        # Rule 3: decision_date <= record_timestamp
        if self.decision_date > self.record_timestamp:
            errors.append("decision_date cannot be after record_timestamp")

        # Rule 4: Registration delay <= 72 hours
        delay = (self.record_timestamp - self.decision_date).total_seconds() / 3600
        if delay > 72:
            errors.append(f"Registration delay {delay:.1f}h exceeds 72h limit")

        # Rule 4 extended: Delay justification required for > 1 hour
        if delay > 1 and not self.delay_justification:
            errors.append("Delay justification required for registration delay > 1 hour")

        if delay > 24 and self.delay_justification:
            if not self.delay_justification.supervisor_approval:
                errors.append("Supervisor approval required for delay > 24 hours")

        # Rule 7: deciders_id non-empty
        if not self.deciders_id:
            errors.append("deciders_id cannot be empty")

        # Rule 9: All signatures must be present
        signer_ids = {s.signer_id for s in self.signatures}
        missing_signers = set(self.deciders_id) - signer_ids
        if missing_signers:
            errors.append(f"Missing signatures from: {missing_signers}")

        # Amendment constraint
        if self.act_type == ActType.AMENDMENT and not self.references:
            errors.append("Amendment requires references field")

        return (len(errors) == 0, errors)


@dataclass
class SpecialDecisionRecord(DecisionRecord):
    """
    Special Decision Record (SDR) - Section 9

    An exception that is pre-defined, recorded before payment,
    public, costly, and auditable.
    """
    is_sdr: bool = True
    exception_type: Optional[ExceptionType] = None
    formal_justification: Optional[str] = None  # min 100 chars
    maximum_term: Optional[datetime] = None
    reinforced_deciders: list[str] = field(default_factory=list)
    oversight_authority: Optional[str] = None

    def validate(self) -> tuple[bool, list[str]]:
        """Validate SDR-specific rules in addition to DR rules."""
        is_valid, errors = super().validate()

        # SDR must have exception_type
        if not self.exception_type:
            errors.append("SDR requires exception_type")

        # Formal justification min 100 chars
        if not self.formal_justification or len(self.formal_justification) < 100:
            errors.append("formal_justification must be at least 100 characters")

        # Maximum term required
        if not self.maximum_term:
            errors.append("SDR requires maximum_term")

        # Reinforced deciders >= 2x normal
        if len(self.reinforced_deciders) < 2 * len(self.deciders_id):
            errors.append("reinforced_deciders must be >= 2x deciders_id count")

        # Oversight authority required
        if not self.oversight_authority:
            errors.append("SDR requires oversight_authority")

        return (len(errors) == 0, errors)


@dataclass
class RevocationRecord:
    """
    Revocation Record (RR) - Section 10

    A decision is revoked exclusively by a Revocation Record.
    Nothing is erased; decisions are revoked, not corrected.
    """
    revocation_id: UUID
    target_decision_id: UUID
    revocation_type: RevocationType
    revocation_reason: str  # min 50 chars
    revoker_authority: str
    revoker_id: list[str]
    revocation_date: datetime
    previous_record_hash: str
    record_timestamp: datetime
    signatures: list[Signature]
    timestamp_attestation: Optional[TimestampAttestation] = None
    org_chart_reference: Optional[dict] = None  # For hierarchical superior

    @classmethod
    def create(
        cls,
        target_decision_id: UUID,
        revocation_type: RevocationType,
        revocation_reason: str,
        revoker_authority: str,
        revoker_id: list[str],
        previous_record_hash: str,
        **kwargs
    ) -> "RevocationRecord":
        """Factory method to create a new Revocation Record."""
        now = datetime.now(timezone.utc)
        return cls(
            revocation_id=uuid4(),
            target_decision_id=target_decision_id,
            revocation_type=revocation_type,
            revocation_reason=revocation_reason,
            revoker_authority=revoker_authority,
            revoker_id=revoker_id,
            revocation_date=now,
            previous_record_hash=previous_record_hash,
            record_timestamp=now,
            signatures=[],
            **kwargs
        )

    def validate(self) -> tuple[bool, list[str]]:
        """Validate the Revocation Record."""
        errors = []

        # Revocation reason min 50 chars
        if len(self.revocation_reason) < 50:
            errors.append("revocation_reason must be at least 50 characters")

        # Must have at least one revoker
        if not self.revoker_id:
            errors.append("revoker_id cannot be empty")

        # All revokers must have signatures
        signer_ids = {s.signer_id for s in self.signatures}
        missing_signers = set(self.revoker_id) - signer_ids
        if missing_signers:
            errors.append(f"Missing signatures from: {missing_signers}")

        return (len(errors) == 0, errors)
