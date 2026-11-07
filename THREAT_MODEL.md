# Threat Model & BYOD Analysis

## 1. Context & Scope

Warm-AntiCheat is designed for programming competitions (such as ICPC-style contests, hackathons, and national olympiads) where participants bring their personal laptops or desktops (BYOD).

Unlike enterprise corporate environments or government-issued hardware:
- The device is not enrolled in a mobile device management (MDM) profile.
- The student or competitor is the device owner and possesses Administrator (Windows) or Root (Linux/macOS) rights.
- Competitions may be held offline or with isolated local network connectivity.

---

## 2. Threat Actor Personas & Capabilities

| Persona | Motivation | Technical Capability | Typical Vector |
| :--- | :--- | :--- | :--- |
| **Casual Cheater** | Gain ranking edge | Standard user knowledge | Running Ollama/ChatGPT in browser, alt-tabbing, connecting to phone hotspot |
| **Technical Participant** | Evade monitoring | Software engineer / programmer | Renaming binaries, killing client process, editing SQLite files, firewalling |
| **Sophisticated Attacker** | Systematic subversion | Advanced developer / reverser | Compiling custom client, tampering with system clock, virtual machine spoofing |

---

## 3. Threat Analysis & Mitigations

### 3.1. Modified Source Code & Recompiled Binaries
- **Threat**: The attacker modifies the open-source client code to ignore prohibited processes or report empty event logs, renames the title, and runs their modified build.
- **Mitigation**:
  - The Contest Builder signs the official release binaries and manifest using an Ed25519 organizer private key.
  - Official contest registration requires matching SHA-256 binary checksums and official digital signatures.
  - Recompiled binaries lack the valid Ed25519 signature from the contest organizer. The Judge Verifier marks submissions from unauthorized binaries as `UNSAFE` or `REVIEW REQUIRED`.

### 3.2. Tampering with Local Audit Logs
- **Threat**: The participant locates the local SQLite database and attempts to delete rows recording prohibited process execution (e.g., `ollama.exe`).
- **Mitigation**:
  - **Asymmetric Encryption**: Individual event payloads are encrypted with AES-256-GCM using an ephemeral key derived from the organizer's public key. The participant cannot read or craft valid ciphertexts.
  - **Tamper-Evident Hash Chain**: Each event contains `sequence_number`, `previous_event_hash`, and `current_event_hash` where $H_n = \text{SHA-256}(H_{n-1} \parallel E_n)$. If any row is deleted or modified, the hash chain breaks.
  - The Judge Verifier detects missing sequence numbers or hash mismatches, classifying the report as `REVIEW REQUIRED`.

### 3.3. Process Killing & Monitoring Interruption
- **Threat**: The participant terminates the monitoring daemon via Task Manager or `kill -9`, runs prohibited code or AI inference, and restarts the client.
- **Mitigation**:
  - The client logs explicit `SystemLifecycle::ApplicationExit` and `SystemLifecycle::ApplicationLaunch` events.
  - Periodic heartbeat events are emitted at fixed intervals.
  - Gaps in heartbeat timestamps or abrupt termination markers indicate monitoring interruption.
  - The Judge Verifier flags gaps exceeding the contest policy threshold as `REVIEW REQUIRED`.

### 3.4. Clock Manipulation
- **Threat**: The participant rolls back the local system clock to confuse event timestamps.
- **Mitigation**:
  - The audit log enforces strictly monotonic sequence numbers alongside timestamps.
  - Backward timestamp jumps in adjacent sequence entries trigger `SequenceAnomaly` detection in the Verifier.

### 3.5. Alternate Operating Systems & Virtual Machines
- **Threat**: The participant runs the client inside a VM while running prohibited tools on the host hypervisor.
- **Mitigation**:
  - Hardware and hypervisor indicators are logged during session initialization.
  - In physical contests, proctor rules mandate physical device inspection and screen visibility.
  - The software transparently records what is observable from within its OS environment without claiming omniscient out-of-band hypervisor detection.

---

## 4. Fundamental BYOD Realities

Warm-AntiCheat adheres to cryptographic and forensic honesty:
> **Security Axiom**: No software running purely in user space on a device controlled by an adversary with root/admin access can guarantee 100% prevention of tampering.

Therefore:
- **`SAFE`** indicates: *No prohibited activity or integrity anomalies were observed within the verified, valid audit log.* It does not constitute a mathematical guarantee that no unauthorized activity occurred out-of-band.
- **`UNSAFE`** indicates: *Verifiable, un-tampered cryptographic evidence of prohibited process execution, restricted domain access, or forged tokens was detected.*
- **`REVIEW REQUIRED`** indicates: *Incomplete, broken, interrupted, or missing evidence that requires human judge investigation and physical proctor review.*
