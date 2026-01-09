"""
Fides Protocol v0.3 - Cryptographic Signatures

Implements Ed25519 signing and verification as recommended by the protocol.
Also supports ECDSA-P256/P384 and RSA-PSS as permitted alternatives.

SPDX-License-Identifier: AGPL-3.0-or-later
"""

import base64
from datetime import datetime, timezone
from typing import Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    SECP256R1,
    SECP384R1,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.exceptions import InvalidSignature

from .records import Signature, SignatureAlgorithm
from .hash_chain import canonical_serialize


PrivateKey = Union[Ed25519PrivateKey, EllipticCurvePrivateKey, RSAPrivateKey]
PublicKey = Union[Ed25519PublicKey, EllipticCurvePublicKey, RSAPublicKey]


def generate_keypair(
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ED25519
) -> tuple[PrivateKey, PublicKey]:
    """
    Generate a new key pair for the specified algorithm.

    Ed25519 is recommended by the protocol (Section 6.3.2).
    """
    if algorithm == SignatureAlgorithm.ED25519:
        private_key = ed25519.Ed25519PrivateKey.generate()
        return private_key, private_key.public_key()

    elif algorithm == SignatureAlgorithm.ECDSA_P256:
        private_key = ec.generate_private_key(SECP256R1())
        return private_key, private_key.public_key()

    elif algorithm == SignatureAlgorithm.ECDSA_P384:
        private_key = ec.generate_private_key(SECP384R1())
        return private_key, private_key.public_key()

    elif algorithm == SignatureAlgorithm.RSA_PSS:
        from cryptography.hazmat.primitives.asymmetric import rsa
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        return private_key, private_key.public_key()

    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def public_key_to_base64(public_key: PublicKey) -> str:
    """Serialize a public key to base64-encoded DER format."""
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der_bytes).decode("ascii")


def base64_to_public_key(b64_key: str) -> PublicKey:
    """Deserialize a base64-encoded DER public key."""
    der_bytes = base64.b64decode(b64_key)
    return serialization.load_der_public_key(der_bytes)


def sign_data(
    private_key: PrivateKey,
    data: bytes,
    algorithm: SignatureAlgorithm,
) -> bytes:
    """Sign data with the private key using the specified algorithm."""
    if algorithm == SignatureAlgorithm.ED25519:
        return private_key.sign(data)

    elif algorithm in (SignatureAlgorithm.ECDSA_P256, SignatureAlgorithm.ECDSA_P384):
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    elif algorithm == SignatureAlgorithm.RSA_PSS:
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.AUTO,
            ),
            hashes.SHA256(),
        )

    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def verify_data(
    public_key: PublicKey,
    signature: bytes,
    data: bytes,
    algorithm: SignatureAlgorithm,
) -> bool:
    """Verify a signature against data. Returns True if valid."""
    try:
        if algorithm == SignatureAlgorithm.ED25519:
            public_key.verify(signature, data)

        elif algorithm in (SignatureAlgorithm.ECDSA_P256, SignatureAlgorithm.ECDSA_P384):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))

        elif algorithm == SignatureAlgorithm.RSA_PSS:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.AUTO,
                ),
                hashes.SHA256(),
            )

        else:
            return False

        return True

    except InvalidSignature:
        return False


def sign_record(
    record,
    signer_id: str,
    private_key: PrivateKey,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ED25519,
) -> Signature:
    """
    Sign a record and return a Signature object.

    The signature is computed over the canonical serialization of the record,
    excluding the signatures field to avoid circular dependency.
    """
    # Serialize the record canonically (excluding signatures)
    record_bytes = canonical_serialize(record, exclude_signatures=True)

    # Sign
    sig_bytes = sign_data(private_key, record_bytes, algorithm)

    # Get public key
    if algorithm == SignatureAlgorithm.ED25519:
        public_key = private_key.public_key()
    elif algorithm in (SignatureAlgorithm.ECDSA_P256, SignatureAlgorithm.ECDSA_P384):
        public_key = private_key.public_key()
    elif algorithm == SignatureAlgorithm.RSA_PSS:
        public_key = private_key.public_key()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return Signature(
        signer_id=signer_id,
        public_key=public_key_to_base64(public_key),
        algorithm=algorithm,
        signature=base64.b64encode(sig_bytes).decode("ascii"),
        signed_at=datetime.now(timezone.utc),
    )


def verify_signature(record, signature: Signature) -> bool:
    """
    Verify a signature on a record.

    Returns True if the signature is valid for the record's canonical form.
    Note: Signatures are excluded from canonical form to avoid circular dependency.
    """
    try:
        # Deserialize the public key
        public_key = base64_to_public_key(signature.public_key)

        # Serialize the record canonically (excluding signatures)
        record_bytes = canonical_serialize(record, exclude_signatures=True)

        # Decode the signature
        sig_bytes = base64.b64decode(signature.signature)

        # Verify
        return verify_data(public_key, sig_bytes, record_bytes, signature.algorithm)

    except Exception:
        return False


def verify_all_signatures(record) -> tuple[bool, list[str]]:
    """
    Verify all signatures on a record.

    Returns (all_valid, list_of_invalid_signer_ids).
    """
    invalid_signers = []

    for signature in record.signatures:
        if not verify_signature(record, signature):
            invalid_signers.append(signature.signer_id)

    return (len(invalid_signers) == 0, invalid_signers)
