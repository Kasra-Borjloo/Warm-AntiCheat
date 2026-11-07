# Cryptographic Architecture & Specifications

Warm-AntiCheat utilizes standard, well-audited cryptographic primitives. Custom encryption schemes and proprietary hashing algorithms are strictly prohibited.

---

## 1. Primitives & Standard Alignment

| Purpose | Algorithm / Primitive | Library / Implementation | Standard |
| :--- | :--- | :--- | :--- |
| **Manifest & Token Signatures** | Ed25519 (Edwards-curve Digital Signature) | `ed25519-dalek` | RFC 8032 |
| **Evidence Key Agreement** | X25519 (Elliptic Curve Diffie-Hellman) | `x25519-dalek` / `curve25519-dalek` | RFC 7748 |
| **Key Derivation** | HKDF-SHA256 (HMAC-based Extract-and-Expand) | `hkdf` crate | RFC 5869 |
| **Authenticated Encryption** | AES-256-GCM (Galois/Counter Mode) | `aes-gcm` crate | NIST SP 800-38D |
| **Tamper-Evident Hash Chains** | SHA-256 (Secure Hash Algorithm) | `sha2` crate | FIPS 180-4 |

---

## 2. Key Separation & Roles

Each competition generates three independent cryptographic keypairs:

```
Contest Cryptographic Hierarchy
├── Manifest Signing Keypair (Ed25519)
│   ├── manifest_signing_key.priv  --> Retained by Contest Organizer
│   └── manifest_signing_key.pub   --> Distributed in Participant & Judge Packages
│
├── Evidence Encryption Keypair (X25519)
│   ├── judge_evidence_key.priv    --> Retained in Judge Package ONLY
│   └── judge_evidence_key.pub     --> Distributed in Participant Client ONLY
│
└── Code Signing Keypair
    └── Used during CI/CD to sign official release binaries
```

### Key Distribution Security Invariant
> **Strict Invariant**: Under no circumstances is the private decryption key (`judge_evidence_key.priv`) or the private manifest signing key (`manifest_signing_key.priv`) ever compiled into or packaged with the distributed Participant Client.

---

## 3. Tamper-Evident Hash Chain Specification

To ensure audit log integrity on participant-controlled devices, events are linked sequentially via a SHA-256 cryptographic chain:

### Initialization (Genesis Event - Sequence 0)
$$\text{Hash}_0 = \text{SHA-256}(\text{"WARM-GENESIS-CHAIN"} \parallel \text{ContestUUID} \parallel \text{ParticipantID})$$

### Subsequent Events (Sequence $i$)
$$\text{Hash}_i = \text{SHA-256}(\text{Seq}_i \parallel \text{Timestamp}_i \parallel \text{Hash}_{i-1} \parallel \text{Category}_i \parallel \text{PayloadHash}_i)$$

Where:
- $\text{Seq}_i$: Strictly monotonically increasing unsigned 64-bit integer ($0, 1, 2, \dots$).
- $\text{Timestamp}_i$: UTC timestamp formatted as RFC 3339 string.
- $\text{Hash}_{i-1}$: 64-character lowercase hexadecimal hash of previous event.
- $\text{Category}_i$: Event category identifier (`Process`, `Browser`, `Network`, `Lifecycle`).
- $\text{PayloadHash}_i$: SHA-256 hash of the canonical JSON event payload.

If an attacker deletes or truncates any event, the subsequent event's $\text{Hash}_{i-1}$ will fail validation when recalculated by the Judge Verifier.

---

## 4. Encrypted Audit Storage Format

Each audit event payload is sealed using AES-256-GCM before being written to SQLite:
1. Client generates an ephemeral X25519 keypair: $(sk_{\text{eph}}, pk_{\text{eph}})$.
2. Client performs Diffie-Hellman with the organizer's public key:
   $$SS = \text{X25519}(sk_{\text{eph}}, pk_{\text{judge}})$$
3. Symmetric encryption key is derived via HKDF:
   $$K_{\text{enc}} = \text{HKDF-SHA256}(\text{salt}=\text{ContestUUID}, \text{IKM}=SS, \text{info}=\text{"WARM-EVENT-AES-256-GCM"})$$
4. Payload is encrypted with a random 96-bit nonce:
   $$\text{Ciphertext}, \text{Tag} = \text{AES-256-GCM-Encrypt}(K_{\text{enc}}, \text{Nonce}, \text{Payload}, \text{AAD}=\text{Seq} \parallel \text{Timestamp})$$
5. The stored record contains $(pk_{\text{eph}}, \text{Nonce}, \text{Ciphertext}, \text{Tag})$.

Only the judge holding $sk_{\text{judge}}$ can reconstruct $SS$ and decrypt the payload.
