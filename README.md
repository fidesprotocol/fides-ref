# fides-ref

**Reference implementation of Fides Protocol v0.3.**

This is the complete reference implementation demonstrating all v0.3 requirements including cryptographic signatures, timestamp attestation, and payment ledger.

---

## Status: In Development

This repository is under active development. See [fides-run](https://github.com/fidesprotocol/fides-run) for a minimal proof of the core logic.

## What This Will Implement

| Spec Section | Status |
|--------------|--------|
| Decision Record (DR) with signatures | Planned |
| Revocation Record (RR) | Planned |
| Special Decision Record (SDR) | Planned |
| Hash Chain (SHA-256) | Planned |
| Cryptographic Signatures (Ed25519) | Planned |
| Timestamp Attestation (RFC 3161) | Planned |
| Payment Ledger | Planned |
| `is_payment_authorized()` | Planned |
| Append-only ledger | Planned |
| Chain integrity verification | Planned |
| 72h registration delay enforcement | Planned |
| SDR expiration enforcement | Planned |
| program_id field | Planned |

## What This Will NOT Implement

| Item | Reason |
|------|--------|
| External Anchor publishing | Requires external infrastructure |
| Role Separation enforcement | Governance, not code |
| Production API | This is reference, not product |
| PKI/CA integration | Requires external CA |

## Requirements

- Python 3.10+
- `cryptography` library (for Ed25519/ECDSA)
- `rfc3161ng` library (for timestamp tokens)

## Protocol Reference

- [Fides Protocol v0.3](https://github.com/fidesprotocol/fides/blob/main/spec/FIDES-v0.3.md)

## Relationship to Other Repos

| Repository | Purpose |
|------------|---------|
| [fides](https://github.com/fidesprotocol/fides) | Protocol specification |
| [fides-run](https://github.com/fidesprotocol/fides-run) | Minimal proof (v0.1 logic) |
| **fides-ref** | Complete reference (v0.3) |
| [fides-compliance-tests](https://github.com/fidesprotocol/fides-compliance-tests) | Test suite for any implementation |

---

## License

AGPLv3 — Same as the protocol.

---

*Reference, not product.*
