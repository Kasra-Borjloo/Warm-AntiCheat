# Privacy Notice & Data Collection Disclosure

Warm-AntiCheat believes that participant privacy and academic integrity must coexist. We maintain complete transparency regarding what data is collected, why it is recorded, how it is secured, and how long it is retained.

---

## 1. What Warm-AntiCheat Collects

During an active competition session, Warm-AntiCheat monitors only competition-relevant metrics:

1. **Process Activity**:
   - Process launch and termination timestamps.
   - Process executable name and PID.
   - Prohibited AI tool detection (e.g., local LLM runtimes such as Ollama, LM Studio, llama.cpp).
2. **Restricted Domain Activity**:
   - Attempts to access explicitly declared restricted domains (e.g. `chatgpt.com`, `claude.ai`, `gemini.google.com`).
   - We **never** record private browsing histories, passwords, form fields, keystrokes, personal search histories, or non-restricted websites.
3. **Network Interface Transitions**:
   - Wi-Fi connection and disconnection timestamps.
   - Connected Wi-Fi SSID name (where accessible).
   - Ethernet link status changes.
   - We **never** inspect packet contents, payloads, or unrelated LAN devices.
4. **System Lifecycle**:
   - Application startup and shutdown.
   - System sleep and wake events.

---

## 2. What Warm-AntiCheat Does NOT Collect

- No webcam or microphone recording.
- No keylogger or arbitrary keyboard capture.
- No arbitrary screen capture or continuous desktop streaming.
- No personal file system indexing or document reading.
- No collection of personal browsing history outside of contest-specified restricted domains.

---

## 3. Asymmetric Protection of Participant Data

All recorded logs are encrypted on the participant's device with the **Judge's public key** using AES-256-GCM. 
- The data is stored locally in an encrypted format.
- Neither the participant nor unauthorized local software can inspect other participants' logs.
- Evidence can only be decrypted by authorized competition judges holding the offline private decryption key.

---

## 4. Data Retention & Deletion

- Audit reports are retained solely for the official competition verification and appeal window (typically 7 to 30 days, as configured by the contest organizer).
- After the verification period, audit evidence may be safely purged.

---

## 5. Security & Antivirus Non-Interference Guarantee

- Warm-AntiCheat respects participant endpoint security. It **does not alter, disable, bypass, or exclude** Windows Defender, macOS Gatekeeper, or third-party antivirus/firewall products.
- No rootkit, kernel driver, or hidden background process is ever deployed.
- The participant is fully in control and informed before monitoring commences.

