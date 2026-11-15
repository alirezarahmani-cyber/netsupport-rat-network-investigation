# NetSupport Manager RAT — Network Incident Investigation Report

**Case:** SOC-NTA-002 | **Incident date:** February 28, 2026  
**Scope:** SOC Tier 1 educational simulation | **Tool:** Wireshark  
**Status:** Tier 1 investigation completed; incident escalation recommended  
**Provisional severity:** High

## 1. Executive Summary

A packet capture from the Easy As 123 exercise was investigated in response to a NetSupport Manager RAT alert. The Windows workstation DESKTOP-TEYQ2NR (10.2.28.88, MAC 00:19:d1:b2:4d:ad) initiated a successful TCP connection to 45.131.214.85:443. HTTP headers, polling messages and recurring requests strongly corroborated the alert. Kerberos and SAMR evidence identified the associated account brolf and its recorded full name Becka Rolf. The evidence supports escalation for potentially unauthorized remote access; actual authorization, initial infection vector and endpoint impact remain unknown.

## 2. Objectives and Dataset

The five primary exercise objectives were to identify the workstation IP, MAC, hostname, username and recorded full name. Additional objectives included network alert validation, timeline reconstruction, indicator extraction and escalation assessment.

Source: [Easy As 123](https://www.malware-traffic-analysis.net/2026/02/28/index.html). See [dataset details](../dataset/README.md).

| Capture property | Value |
|---|---|
| File | 2026-02-28-traffic-analysis-exercise.pcap |
| Size | 6,581 KB |
| Format / encapsulation | PCAP / Ethernet |
| Packets | 15,512 |
| Captured packet bytes | 6,333,775 |
| Average size / rate | 408 bytes / 1.0 packets/s |
| Duration | 04:21:29 |
| First frame UTC | 2026-02-28 19:55:06.482909 |
| Recorded SHA-256 | 3dc470f5490ec15b4024c513e87c67e0b17caeae2a2ce3d83541be24ef407e61 |

The capture begins in the same minute as the reported alert (19:55 UTC). The exact ordering of the initial alert and first frame is not established because the alert time has minute-level precision. The hash is an evidence integrity baseline, not independent proof of authenticity or a malware hash.

## 3. Methodology

Passive Wireshark inspection: capture metadata, protocol hierarchy, endpoints and conversations, TCP handshake, application protocol, NBNS, Kerberos, SAMR, targeted related activity, evidence correlation and assessment.

| Purpose | Display filter |
|---|---|
| Internal host | `ip.addr == 10.2.28.88` |
| Alert endpoint | `ip.addr == 45.131.214.85` |
| TCP stream | `tcp.stream eq 40` |
| Hostname | `nbns && ip.addr == 10.2.28.88` |
| Authentication | `kerberos && ip.addr == 10.2.28.88` |
| Directory context | `ldap && ip.addr == 10.2.28.88` |
| Full name | `samr && ip.addr == 10.2.28.88` |
| Prior HTTP requests | `ip.addr == 10.2.28.88 && frame.number < 2569 && http.request` |
| Prior DNS queries | `ip.src == 10.2.28.88 && frame.number < 2569 && dns.flags.response == 0` |

## 4. Network Context

The exercise specifies subnet 10.2.28.0/24, domain easyas123.tech, NetBIOS domain EASYAS123, domain controller 10.2.28.2 and gateway 10.2.28.1. DNS frames 12–13 resolve easyas123-dc.easyas123.tech to 10.2.28.2. LDAP RootDSE frames 2661/2663 corroborate the directory context; the latter response was available as analyst-extracted text.

TCP appears in 12,544 packets (80.9%); TLS in 1,857 (12.0%, 46.0% attributed bytes); HTTP in 354 (2.3%, 18.3% attributed bytes). DNS, NBNS, Kerberos, LDAP, SMB2 and DCE/RPC support identification. Protocol hierarchy packet percentages overlap across layers. Four malformed packets were observed under the LSA branch; their security relevance was not established.

There were 104 IPv4 endpoints and 102 IPv4 conversations. The principal internal address 10.2.28.88 appeared in 14,673 IPv4 packets. The alert endpoint appeared in 550 packets. Traffic volume alone does not establish compromise.

## 5. Technical Findings

### F-001 — Alert-associated TCP connection

The internal endpoint 10.2.28.88:51912 communicated with 45.131.214.85:443, TCP stream 40 (IPv4 stream 25). The conversation contained 550 packets, 276 outbound and 274 inbound, with approximately 79 KB outbound and 17 KB inbound. Its observed span was 15,637.3601 seconds (4 h 20 min 37 s).

| Frame | UTC time | Flags |
|---|---|---|
| 2569 | 19:55:51.373340 | SYN, internal to remote |
| 2636 | 19:55:51.523685 | SYN/ACK, remote to internal |
| 2637 | 19:55:51.523688 | ACK, internal to remote |

The workstation initiated and established the connection. Duration is the interval between observed packets, not proof of continuous activity.

### F-002 — MAC address

Ethernet/IPv4 headers in frames 7, 1357 and 12953 associate 10.2.28.88 with 00:19:d1:b2:4d:ad. In routed traffic the remote-facing Ethernet address belongs to a local next hop, not the Internet server.

### F-003 — NetSupport application indicators

Frame 2638 contains an HTTP POST over TCP 443 to the request path `/fakeurl.htm`, with User-Agent `NetSupport Manager/1.3`, Content-Type `application/x-www-form-urlencoded` and Connection `Keep-Alive`. Its body contains `CMD=POLL`, `INFO=1` and `ACK=1`.

Frame 2639 returns HTTP/1.1 200 OK, Server `NetSupport Gateway/1.92 (Windows NT)`, and `CMD=ENCD`, `ES=1`, and opaque `DATA` fields. Further exchanges appear in frames 2640–2641. The HTTP headers are readable and Wireshark flags unencrypted HTTP on a port normally used for encrypted communication. The opaque application payload was not decoded; its exact encoding or encryption is unverified. POST does not establish file upload.

The combined indicators strongly corroborate NetSupport-compatible communication. The product has legitimate administrative uses, so authorization and malicious use require separate validation.

### F-004 — Recurring communication

Frames 3807, 4093, 4134, 4149, 4201 and 4211 show recurring POST requests approximately 60 seconds apart, beginning at 19:56:52.414979 UTC. This is consistent with polling or beaconing-like behavior. The full interval distribution was not measured; no specific remote command execution or exfiltration was established.

### F-005 — Hostname

NBNS frame 135 registers DESKTOP-TEYQ2NR with suffix 0x20 and explicitly associates it with 10.2.28.88. Frame 136 shows suffix 0x00. These suffixes describe NetBIOS name types and are not part of the hostname. Frame 137 is consistent with the domain context. The MAC and IP evidence corroborates the workstation identity.

### F-006 — User account

Kerberos AS-REQ frame 251 contains client principal brolf, requested realm EASYAS123, service krbtgt and NetBIOS address DESKTOP-TEYQ2NR. AS-REP frame 253 explicitly responds to 251 and contains a TGT for brolf in realm EASYAS123.TECH (ticket service krbtgt). Ticket issuance establishes the account association, not interactive desktop logon or responsibility for the RAT.

### F-007 — Recorded full name

SAMR QueryUserInfo request frame 338 and response frame 339 associate Account Name brolf with Full Name Becka Rolf. Both values appear in the same returned account structure. The result is direct evidence, not a guess based on naming conventions.

See [findings and evidence links](../evidence/findings.md).

## 6. Related Activity

- TLS connection to 23.64.147.24:443 (frames 1357–1365, 1374): SNI www.fmcsa.dot.gov; TLS 1.3 records. No direct relationship to the alert was established; encrypted content was not verified.
- HTTP to 23.218.232.148:80: two TCP connections from local ports 62034 and 62035; frames 12963/12966 and 12969/12972 show sequential byte-range retrieval, HTTP 206, Microsoft BITS/7.8 and Host msedge.b.tlu.dl.delivery.mp.microsoft.com. Content-Type application/x-chrome-extension is consistent with Edge-related retrieval. This reviewed activity occurred after the first NetSupport connection. File authenticity and installation were not verified.
- Prior HTTP: frame 87 GET /connecttest.txt and frame 89 HTTP 200 with text/plain body Microsoft Connect Test (22 bytes) are consistent with Windows NCSI. The other nine matching messages were SSDP M-SEARCH requests. No related executable/script download was established in this review.
- DNS lead: frames 1559 and 1747 query vadusa.xyz immediately before the first NetSupport SYN; the latter is marked retransmission. The DNS response and linkage to the alert endpoint were not verified. The domain is not a confirmed IOC.

The capture starts approximately 45 seconds before the first observed NetSupport SYN. Initial access or installation may have occurred earlier. The infection vector remains undetermined; a comprehensive initial-access investigation was outside the completed Tier 1 scope.

## 7. Indicators and Timeline

[IOC table (CSV)](../evidence/iocs.csv) — principal indicator: 45.131.214.85:443/TCP. Application context includes `/fakeurl.htm`, NetSupport headers, CMD=POLL, CMD=ENCD and recurring POSTs. These are best evaluated together; port 443 or a legitimate product name alone is not proof of malicious activity. No malware file hash was obtained.

[Investigation timeline (CSV)](../evidence/timeline.csv) — UTC events from DHCP and domain discovery through authentication, NetSupport connection and recurring communication. Chronology is not proof of causation.

## 8. Impact, Confidence and Severity

**Confirmed:** one workstation communicating with the alert endpoint; successful TCP/HTTP exchange; NetSupport-compatible indicators; recurring requests; host/account identity. High confidence applies to these observations.

**Suspected:** unauthorized remote access or C2 (medium confidence in malicious-use hypothesis). **Provisional severity: High**, based on alert corroboration and potential impact. Actual severity depends on authorization, asset criticality and organizational policy.

**Unestablished:** initial access, endpoint process identity, installation, persistence, attacker commands, credential theft, exfiltration, lateral movement, additional affected systems and user responsibility. Potential consequences are not confirmed outcomes.

## 9. Escalation and Recommendations

Escalate to SOC Tier 2 / Incident Response. Review EDR/process telemetry and installation/authorization records; preserve logs and forensic evidence; investigate initial access and persistence; hunt for related network indicators; assess command execution, data access and wider scope. Consider endpoint isolation and remote endpoint blocking only under approved incident response procedures. No containment or remediation was performed in this simulation.

## 10. Official Exercise Answers

| Attribute | Value |
|---|---|
| IP | 10.2.28.88 |
| MAC | 00:19:d1:b2:4d:ad |
| Hostname | DESKTOP-TEYQ2NR |
| Username | brolf |
| Recorded full name | Becka Rolf |

All five primary identification objectives are complete.

## 11. Limitations and Conclusion

The available evidence is network traffic, not endpoint forensic artifacts or software authorization records. Capture hardware, original filter and dropped packet count were unknown; pre-capture activity was not available. TLS and opaque NetSupport payloads were not decrypted. The full periodicity distribution and DNS lead were not resolved. No malware executable was extracted or analyzed. The report is based on analyst-collected Wireshark evidence; the original PCAP was not independently reanalyzed in preparing this package.

The alert is strongly corroborated and the Tier 1 investigation is complete. Escalation is recommended; this does not imply the incident is remediated or resolved.

## 12. Evidence Index

- [01-03_capture_file_properties.png](../evidence/screenshots/01-03_capture_file_properties.png)
- [01-03_utc_timestamp_verification.png](../evidence/screenshots/01-03_utc_timestamp_verification.png)
- [01-04_protocol_hierarchy.png](../evidence/screenshots/01-04_protocol_hierarchy.png)
- [02-01_ipv4_endpoints.png](../evidence/screenshots/02-01_ipv4_endpoints.png)
- [02-01_ipv4_conversations.png](../evidence/screenshots/02-01_ipv4_conversations.png)
- [02-01_tcp_conversations.png](../evidence/screenshots/02-01_tcp_conversations.png)
- [02-02_suspicious_tcp_handshake.png](../evidence/screenshots/02-02_suspicious_tcp_handshake.png)
- [02-03_mac_dns_frame7.png](../evidence/screenshots/02-03_mac_dns_frame7.png)
- [04-02_external_tls_connection.png](../evidence/screenshots/04-02_external_tls_connection.png)
- [02-04_nbns_hostname_identification.png](../evidence/screenshots/02-04_nbns_hostname_identification.png)
- [03-01_kerberos_as_req.png](../evidence/screenshots/03-01_kerberos_as_req.png)
- [03-01_kerberos_as_rep.png](../evidence/screenshots/03-01_kerberos_as_rep.png)
- [03-02_ldap_rootdse_context.png](../evidence/screenshots/03-02_ldap_rootdse_context.png)
- [03-03_samr_full_name_identification.png](../evidence/screenshots/03-03_samr_full_name_identification.png)
- [04-02_microsoft_tcp_connections.png](../evidence/screenshots/04-02_microsoft_tcp_connections.png)
- [04-02_microsoft_http_request.png](../evidence/screenshots/04-02_microsoft_http_request.png)
- [04-02_microsoft_http_response.png](../evidence/screenshots/04-02_microsoft_http_response.png)
- [04-02_repeated_range_requests.png](../evidence/screenshots/04-02_repeated_range_requests.png)
- [04-04_netsupport_http_post.png](../evidence/screenshots/04-04_netsupport_http_post.png)
- [04-04_netsupport_gateway_response.png](../evidence/screenshots/04-04_netsupport_gateway_response.png)
- [04-04_netsupport_repeated_requests.png](../evidence/screenshots/04-04_netsupport_repeated_requests.png)
- [04-04_netsupport_http_stream.png](../evidence/screenshots/04-04_netsupport_http_stream.png)
- [04-05_pre_connection_http_requests.png](../evidence/screenshots/04-05_pre_connection_http_requests.png)
- [04-05_ncsi_http_response.png](../evidence/screenshots/04-05_ncsi_http_response.png)
- [04-05_dns_unverified_lead.png](../evidence/screenshots/04-05_dns_unverified_lead.png)

*Educational investigation using a publicly provided training dataset. No production systems were targeted.*

