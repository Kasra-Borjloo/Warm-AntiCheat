# Participant Client User Guide

The **Participant Client** (`apps/participant`) is installed on contestants' personal computers during programming competitions.

---

## 1. Installation & System Requirements

- **Windows**: Windows 10 or 11 (64-bit or ARM64)
- **Linux**: Ubuntu 20.04+, Debian 11+, Fedora, Arch (glibc 2.31+)
- **macOS**: macOS 12 Monterey or newer (Intel & Apple Silicon)

No external database or administrative daemon installation is required.

---

## 2. Enrollment & Starting a Session

1. **Launch Application**: Open the client distributed for your contest (e.g., `GOCUP-1-Client.exe`).
2. **Review Privacy Disclosure**: The client clearly displays:
   - Contest Name & Organizer
   - Categories of monitored activity (Process executions, restricted domain access, network state)
   - Stated retention period
3. **Enter Credentials**:
   - **Participant ID**: Your assigned ID (e.g., `team-42`).
   - **Enrollment Token**: The cryptographically signed token issued by proctors.
4. **Session Activation**:
   - Click **"Start Competition Session"**.
   - The status indicator turns **Green (Active)**.
   - The application begins logging audit events into its encrypted local store.

---

## 3. During the Competition

- Keep the Participant Client running in the background.
- Do not launch prohibited AI tools (e.g. Ollama, LM Studio) or navigate to restricted web domains.
- If your device sleeps or restarts, re-open the client; the session will log a resume marker and continue the hash chain.

---

## 4. Exporting Evidence at Contest End

When the contest finishes or when a proctor approaches your station:
1. Insert the authorized Judge USB drive (or select an export directory).
2. Click **"Export Evidence"**.
3. The client exports an encrypted `.warm-evidence` bundle.
4. The proctor collects the USB drive for forensic verification in the Judge Verifier.
