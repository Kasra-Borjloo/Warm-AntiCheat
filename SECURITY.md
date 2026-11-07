# Security Policy & Vulnerability Reporting

## 1. Security Model & Assumptions

Warm-AntiCheat operates under a realistic **Bring-Your-Own-Device (BYOD)** threat model:
- The participant is assumed to have full Administrator or Root privileges on their machine.
- The complete source code of Warm-AntiCheat is open source and publicly inspectable.
- Participants may compile custom software, inspect memory, or attempt local proxying.
- Network access during contests may be restricted, firewalled, or completely disconnected.

Given these real-world constraints, Warm-AntiCheat **does not rely on security through obscurity**, fake kernel magic, or unsupported claims of unhackable client software. Instead, it relies on:
1. **Mathematical non-repudiation**: Ed25519 digital signatures ensure official binaries and contest configurations cannot be forged.
2. **Asymmetric data containment**: All recorded audit events are encrypted using judge public keys (X25519 + AES-256-GCM); participants cannot read or decrypt the contents of audit files.
3. **Tamper-evident sequence logging**: SHA-256 hash chains guarantee that any dropped, reordered, modified, or truncated event is cryptographically detectable by the Judge Verifier.
4. **Transparent classification**: The system does not silently ban students based on false positives. It produces explainable timelines categorized into `SAFE`, `UNSAFE`, and `REVIEW REQUIRED`.

---

## 2. Cryptographic Controls

- **Digital Signatures**: Ed25519 (`ed25519-dalek`) with RFC 8032 compliance.
- **Key Exchange**: X25519 (`curve25519-dalek` / `x25519-dalek`) for Diffie-Hellman key agreement.
- **Key Derivation**: HKDF-SHA256 (`hkdf` crate, RFC 5869) for symmetric session key derivation.
- **Authenticated Encryption**: AES-256-GCM (`aes-gcm` crate, NIST SP 800-38D) with 96-bit unique nonces.
- **Cryptographic Hashing**: SHA-256 (`sha2` crate, FIPS 180-4) for event hash chaining and file integrity manifests.

---

## 3. Reporting a Security Vulnerability

If you discover a security flaw or cryptographic weakness in Warm-AntiCheat, please report it responsibly:
- **Primary Contact**: Kasra Borjloo (<kasraborjloo2009@gmail.com>)
- **Repository Issues**: For public discussion of non-sensitive improvements, use GitHub Issues. For vulnerabilities that could compromise active competitions, please use private email contact.

When submitting a vulnerability report, please include:
1. Description of the attack vector and preconditions.
2. Operating system and hardware environment.
3. Proof-of-concept steps or code demonstrating the bypass or tampering.
4. Assessment of whether the tamper attempt is detected as `REVIEW REQUIRED` or bypassed silently.

---

## 4. Antivirus Compatibility, Safe Desktop Practices & False-Positive Remediation

Warm-AntiCheat is built to function cooperatively and transparently alongside endpoint protection systems:
- **No Antivirus Tampering**: The software will never request that participants disable Windows Defender or third-party antivirus software, nor will it add registry exclusions or kill security services.
- **Documented APIs**: All telemetry uses documented, sanctioned operating system interfaces (Win32 Toolhelp snapshot, IP Helper API, standard event notifications).
- **False-Positive Investigation Protocol**: Antivirus detections (such as Bkav Pro `W32.Malware.9E43BB5C` or Defender SmartScreen unknown publisher warnings) are treated as actionable investigation signals. Official dispute submissions and whitelisting requests are filed directly with vendors rather than employing evasive binary packing or obfuscation.
- For complete operational procedures, refer to [ANTIVIRUS_COMPATIBILITY.md](ANTIVIRUS_COMPATIBILITY.md).

