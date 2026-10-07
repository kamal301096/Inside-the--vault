# Inside the Vault: Windows Server 2022 Security Baseline, Validation & Adversary Emulation

[![Framework: NIST SP 800-115](https://img.shields.io/badge/Framework-NIST%20SP%20800--115-blue.svg)](https://csrc.nist.gov/publications/detail/sp/800-115/final)
[![Standard: NIST SP 800-53 Rev. 5](https://img.shields.io/badge/Standard-NIST%20SP%20800--53%20Rev.5-0052CC.svg)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
[![Alignment: CompTIA Security+](https://img.shields.io/badge/Aligned-CompTIA%20Security%2B%20SY0--701-red.svg)](https://www.comptia.org/certifications/security)
[![MITRE ATT&CK Mapping](https://img.shields.io/badge/Adversary%20Emulation-MITRE%20ATT%26CK-orange.svg)](https://attack.mitre.org/)

A controlled, end-to-end technical security assessment evaluating Windows Server 2022 endpoint resilience, automated cryptographic baselining, and detection capabilities against CompTIA Security+ (SY0-701) and NIST SP 800-115 methodologies.

---

## Project Repository Contents

* `Inside the Vault — Senior Management Report.docx`: Executive summary, business impact analysis, compliance exposure (ISO 27001, PCI-DSS, HIPAA), and a three-phase remediation plan.
* `Inside the Vault (Final Project) - Technical Assessment Report .docx`: Comprehensive 10-section technical documentation covering discovery cmdlets, payload staging, defense neutralization, and telemetry verification.
* `Windows_Server_2022_Security_Baseline_Commands.xlsx`: Complete baseline command dictionary and PowerShell audit execution scripts.

---

## Executive Overview

The assessment evaluated whether built-in host telemetry could identify and trace an adversary after endpoint prevention controls were fully neutralized. 

* **Target System**: Windows Server 2022 Standard (`192.168.64.130`, Hostname: `WIN-IVM8CN18AH7`).
* **Attacker System**: Kali Linux (`192.168.64.129`, Hostname: `red`).
* **Network Boundary**: Isolated host-only virtual subnet (`192.168.64.0/24`).
* **Core Takeaway**: While commodity payload execution succeeded once defenses were lowered, native Windows telemetry (`Get-NetTCPConnection` and `Get-Process`) immediately exposed the unauthorized outbound socket on port `1122` and mapped it back to an unsigned binary executing from `\Downloads`. Automated baseline monitoring acts as an essential forensic safety net when preventive controls fail.

---

## Lab Architecture & Egress Topology

```text
+---------------------------------------+          SFTP Ingress (Port 22)           +---------------------------------------+
|             Kali Linux                | ----------------------------------------> |          Windows Server 2022          |
|           "red" (Attacker)            |                                           |          "WIN-IVM8CN18AH7"            |
|            192.168.64.129             | <---------------------------------------- |            192.168.64.130             |
|       Handler: TCP Port 1122          |         Meterpreter Reverse C2 Egress     |      Dynamic Source: Port 50158       |
+---------------------------------------+                                           +---------------------------------------+
```
## Assessment Execution Lifecycle

### 1. Discovery Phase (Defensive Baselining)
* **10-Category Baseline Extraction**: Captured baseline evidence across System Identity, Local Accounts & Groups, Services & Startup, Network & Listening Ports, Windows Firewall, Scheduled Tasks, Software & Patches, SMB Shares, Audit Policy, and Processes.
* **Cryptographic Evidence Manifest**: Automated PowerShell collection into structured logs under `C:\SecurityBaseline\03_Logs\` and generated SHA-256 integrity hashes (`Baseline_Manifest_[Timestamp].txt`) to ensure non-repudiation.

### 2. Attack Phase (Adversary Emulation)
* **Payload Generation**: Created a 64-bit Meterpreter reverse TCP binary (`windows/x64/meterpreter_reverse_tcp`) targeting `192.168.64.129:1122` (size: 262,656 bytes).
* **Ingress Staging**: Transferred the payload securely over SFTP via WinSCP directly into `C:\Users\Administrator\Downloads`.
* **Defense Impairment (T1562.001)**: Deliberately disabled Microsoft Defender Real-Time Protection, Cloud-Delivered Protection, Automatic Sample Submission, Tamper Protection, and all three Windows Firewall profiles (Domain, Private, Public).
* **Masquerading Validation (T1036.002)**: Demonstrated extension spoofing using the Unicode Right-to-Left Override character (`U+202E`), disguising the executable as `payload[U+202E]3pm.mp4`.
* **Execution & C2 Callback (T1071 / T1204)**: Executed the payload, successfully establishing an interactive Command-and-Control session with dynamic source port `50158`.

### 3. Post-Execution Telemetry & Static Analysis
* **Network Socket Anomaly**: `Get-NetTCPConnection -State Established` flagged an active socket connecting out to `192.168.64.129:1122`.
* **PID Resolution**: `Get-Process -Id 5204` mapped the anomalous connection directly to `C:\Users\Administrator\Downloads\payload.exe`.
* **Static Threat Intelligence**: Computed on-disk SHA-256 (`22D04F38015DA265E6ED404491919B96024B0B5460C949B9DD1DBAE47CFBEF20`). VirusTotal analysis returned a **47/71 vendor detection rate**, confirming commodity tooling rather than an advanced zero-day exploit.

---

## Baseline vs. Compromised State Telemetry

| Telemetry Focus Area | Known-Good Baseline State | Impaired / Compromised State | Diagnostic Verification Cmdlet |
| :--- | :--- | :--- | :--- |
| **Endpoint Antivirus** | Real-time & Tamper Protection active | Disabled / Tamper Protection bypassed | `Get-MpComputerStatus` |
| **Host Firewall** | Enabled on Domain, Private, and Public | All profiles disabled (`False`) | `Get-NetFirewallProfile` |
| **Active Sockets** | Only approved listening ports (135, 445, 5985) | Established egress socket to `192.168.64.129:1122` | `Get-NetTCPConnection -State Established` |
| **Process Staging** | Binaries run from `System32` / `Program Files` | Process executing from user directory (`\Downloads`) | `Get-Process -Id <PID> \| Select Path` |
| **Integrity Checks** | Hash matches documented manifest | Unregistered executable present | `Get-FileHash -Algorithm SHA256` |

---

## Governance, Risk & Control Traceability Matrix

| Finding ID | Finding Description | Rating | MITRE ATT&CK | NIST SP 800-53 Rev. 5 | CompTIA Security+ Domain |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **F-01** | Documented Baseline & Cryptographic Integrity | Positive Control | N/A | CM-2, CM-6, SI-7 | Security Architecture & Hardening |
| **F-02** | Total Impairment of Endpoint Prevention Controls | Critical | T1562.001 | SI-3, SC-7, CM-7 | Endpoint Protection & Defense Evasion |
| **F-03** | Arbitrary Execution from User-Writable Folders | High | T1036.002, T1105 | SI-3, AC-6 | Threat Vectors & Endpoint Security |
| **F-04** | Active C2 Reverse Egress Over Non-Standard Port | Critical | T1071, T1204 | SC-7, IR-4, SI-4 | Indicators of Compromise & Network Ops |
| **F-05** | Native Host Telemetry Anomaly Detection | Positive Control | N/A | AU-6, SI-4 | Security Operations & Incident Response |
| **F-06** | Commodity Artifact Detection (47/71 VT Score) | Informational | N/A | RA-5, SI-3 | Vulnerability & Threat Analysis |

---

## Prioritized Remediation Roadmap

* **Phase 1: Immediate Containment (P1 — Immediate)**
  * Centrally enforce Microsoft Defender Tamper Protection via GPO/Intune to prevent local administrator disablement.
  * Implement Application Control (WDAC / AppLocker) blocking executable code execution from user-writable paths (`C:\Users\*`, `\Downloads`, `\Temp`).
* **Phase 2: Network Hardening & Egress Control (P2 — Short-Term)**
  * Restrict outbound server egress traffic at the firewall perimeter to explicitly authorized destination ports (80, 443, 53), immediately dropping non-standard egress connections like port 1122.
  * Strip routine administrative privileges; implement Privileged Access Workstations (PAWs) and Just-in-Time (JIT) access.
* **Phase 3: Telemetry Automation & Monitoring (P3 — Strategic)**
  * Ingest Event ID 4688 (with Command-Line Process Auditing enabled) and Sysmon Event ID 3 into a centralized SIEM.
  * Automate scheduled baseline drift audits via PowerShell tasks to alert when hashes or services deviate from the approved baseline.

---

## Indicators of Compromise (IOCs)

* **File Name**: `payload.exe` (Disguised variation: `payload[U+202E]3pm.mp4`)
* **Staged Path**: `C:\Users\Administrator\Downloads\payload.exe`
* **File Size**: 262,656 bytes (256.50 KB)
* **SHA-256**: `22D04F38015DA265E6ED404491919B96024B0B5460C949B9DD1DBAE47CFBEF20`
* **MD5**: `cb600a478b957afc66757070742e0fe1`
* **PE Imphash**: `c2d02fc98f1d75d7b9457468ec75da0e`
* **C2 Listener**: `192.168.64.129:1122` (TCP)
* **Observed Target Socket**: `192.168.64.130:50158` (State: Established)
