# NetSupport Manager RAT — Network Incident Investigation

![Wireshark](https://img.shields.io/badge/Wireshark-Network%20Analysis-1679A7?logo=wireshark&logoColor=white)
![SOC](https://img.shields.io/badge/SOC-Tier%201-blue)
![Status](https://img.shields.io/badge/Investigation-Completed-success)
![Severity](https://img.shields.io/badge/Severity-High-red)

## Project Overview

This project documents a hands-on SOC Tier 1 network investigation of suspected NetSupport Manager RAT activity using Wireshark.

The investigation is based on the **Easy As 123** traffic analysis exercise published by Malware-Traffic-Analysis.net on February 28, 2026.

The objective was to validate the reported security alert, identify the affected Windows workstation and associated user account, analyze suspicious network communication, extract relevant indicators, and establish an evidence-based incident escalation decision.

## Investigation Summary

| Property | Details |
|---|---|
| Incident Date | February 28, 2026 |
| Investigation Type | Network Traffic Analysis |
| Analyst Role | SOC Analyst Tier 1 — Simulation |
| Primary Tool | Wireshark |
| Total Packets | 15,512 |
| Capture Duration | 4 hours, 21 minutes, 29 seconds |
| Reported Threat | NetSupport Manager RAT |
| Provisional Severity | High |
| Final Disposition | Escalate to Tier 2 / Incident Response |

## Investigation Objectives

- Perform initial PCAP triage and protocol analysis.
- Identify suspicious internal and external network endpoints.
- Establish the affected workstation's IP, MAC address, and hostname.
- Identify the associated user account and its recorded full name.
- Analyze TCP sessions and application-layer communication.
- Validate NetSupport-related network indicators.
- Reconstruct the investigation timeline.
- Extract indicators of compromise and assess incident severity.
- Produce a professional incident investigation report.

## Investigation Workflow

    Initial Triage
          |
          v
    Endpoints & Conversations
          |
          v
    Host Identification
          |
          v
    User Attribution
          |
          v
    RAT Network Investigation
          |
          v
    Evidence Correlation & IOC Extraction
          |
          v
    Incident Assessment & Escalation
          |
          v
    Final Incident Report

## Key Findings

### 1. Affected Workstation Identification

| Attribute | Identified Value |
|---|---|
| Internal IP | 10.2.28.88 |
| MAC Address | 00:19:d1:b2:4d:ad |
| Hostname | DESKTOP-TEYQ2NR |
| Associated Username | brolf |
| Recorded Full Name | Becka Rolf |
| Active Directory Domain | easyas123.tech |

The workstation identity was established through Ethernet, IPv4, and NBNS packet inspection.

Kerberos authentication and SAMR account information were subsequently correlated to identify the associated user account.

### 2. Suspicious Network Communication

| Attribute | Observed Value |
|---|---|
| Internal Endpoint | 10.2.28.88:51912 |
| Remote Endpoint | 45.131.214.85:443 |
| Transport Protocol | TCP |
| Application Protocol | HTTP/1.1 |
| TCP Stream | 40 |
| Total Packets | 550 |
| Observed Duration | Approximately 4 hours and 20 minutes |
| Outbound Traffic | Approximately 79 KB |
| Inbound Traffic | Approximately 17 KB |

Packet-level analysis confirmed that the internal workstation initiated a successful TCP connection to the remote endpoint identified in the initial security alert.

The communication used unencrypted HTTP on TCP port 443 and contained application identifiers consistent with NetSupport Manager.

### 3. NetSupport Application Indicators

The following indicators were identified through HTTP request, response, and stream inspection:

- HTTP POST requests to `/fakeurl.htm`
- User-Agent: `NetSupport Manager/1.3`
- Server header: `NetSupport Gateway/1.92 (Windows NT)`
- Application message: `CMD=POLL`
- Application message: `CMD=ENCD`
- Recurring HTTP POST requests at approximately 60-second intervals within the reviewed sequence.

The combined indicators strongly corroborated the reported NetSupport alert.

NetSupport Manager is a legitimate remote administration product that can also be abused for unauthorized remote access. Its presence alone does not establish malicious use.

## Technical Evidence

| Finding | Primary Evidence |
|---|---|
| Suspicious TCP connection | Frames 2569, 2636, 2637 |
| MAC address identification | Frames 7, 1357 |
| Hostname identification | NBNS frames 135, 136 |
| Account authentication | Kerberos frames 251, 253 |
| Full name identification | SAMR frame 339 |
| NetSupport client request | HTTP frame 2638 |
| NetSupport Gateway response | HTTP frame 2639 |
| Recurring communication | Frames 3807, 4093, 4134, 4149, 4201, 4211 |

## Indicators of Compromise

| Indicator | Value | Classification |
|---|---|---|
| Remote IP | 45.131.214[.]85 | Alert-associated network indicator |
| Destination Port | TCP 443 | Connection context |
| HTTP URI | /fakeurl.htm | Application indicator |
| User-Agent | NetSupport Manager/1.3 | Application indicator |
| Server Header | NetSupport Gateway/1.92 | Application indicator |
| Communication Pattern | Recurring HTTP POST requests | Behavioral indicator |

These indicators should be evaluated collectively rather than treated as independently conclusive evidence of malicious activity.

## Tools and Skills Demonstrated

- Wireshark packet inspection and display filtering
- PCAP metadata and protocol hierarchy analysis
- IPv4 endpoint and TCP conversation analysis
- TCP three-way handshake validation
- HTTP request and response analysis
- TCP and HTTP stream investigation
- DNS and NBNS analysis
- Active Directory network traffic analysis
- Kerberos authentication and ticket inspection
- SAMR account information extraction
- Host and user evidence correlation
- Network IOC identification
- Incident timeline reconstruction
- SOC alert triage, severity assessment, and escalation
- Professional cybersecurity documentation

## Repository Structure

    netsupport-rat-network-investigation/
    |
    |-- README.md
    |
    |-- report/
    |   |-- incident-investigation-report.md
    |
    |-- evidence/
    |   |-- screenshots/
    |   |-- findings.md
    |   |-- timeline.csv
    |   |-- iocs.csv
    |
    |-- dataset/
        |-- README.md

## Final Security Assessment

The investigation successfully identified the workstation and associated account involved in the reported NetSupport communication.

The observed TCP session, NetSupport-specific application identifiers, and recurring polling-like requests strongly corroborated the initial security alert.

**Provisional Severity:** High

**Recommended Action:** Escalate to SOC Tier 2 / Incident Response.

The initial infection vector, software authorization status, endpoint process identity, and actual endpoint impact remain undetermined. These matters require additional endpoint-level investigation.

The available network evidence was sufficient to complete the Tier 1 investigation and establish an appropriate escalation decision.

## Dataset

The original training dataset and exercise are available at:

[Malware-Traffic-Analysis.net — Easy As 123 (February 28, 2026)](https://www.malware-traffic-analysis.net/2026/02/28/index.html)

The raw PCAP and potentially malicious files are not redistributed in this repository.

## Disclaimer

This project was completed for educational purposes using a publicly available cybersecurity training dataset.

All analysis was performed as part of a simulated SOC investigation. No production systems were targeted, and no containment or remediation actions were performed.

## Author

**Alireza Rahmani**

Cybersecurity Portfolio | SOC Analysis | Network Traffic Investigation

[GitHub Profile](https://github.com/alirezarahmani-cyber)
