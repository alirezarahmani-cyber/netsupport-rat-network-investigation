# Findings and Confidence Assessment

| ID | Finding | Frames | Status | Confidence | Screenshot |
|---|---|---|---|---|---|
| F-001 | Alert-associated TCP connection | 2569, 2636, 2637 | Confirmed | High | [Evidence](screenshots/02-02_suspicious_tcp_handshake.png) |
| F-002 | Internal MAC 00:19:d1:b2:4d:ad | 7, 1357, 12953 | Confirmed | High | [Evidence](screenshots/02-03_mac_dns_frame7.png) |
| F-003 | NetSupport-compatible HTTP communication | 2638–2641 | Confirmed indicators | High | [Evidence](screenshots/04-04_netsupport_http_post.png) |
| F-004 | Recurring HTTP POST requests, approximately 60 seconds apart in reviewed sequence | 3807, 4093, 4134, 4149, 4201, 4211 | Confirmed observed pattern | High | [Evidence](screenshots/04-04_netsupport_repeated_requests.png) |
| F-005 | Hostname DESKTOP-TEYQ2NR | 135, 136 | Confirmed | High | [Evidence](screenshots/02-04_nbns_hostname_identification.png) |
| F-006 | Account brolf and TGT issuance | 251, 253 | Confirmed | High | [Evidence](screenshots/03-01_kerberos_as_rep.png) |
| F-007 | Recorded full name Becka Rolf | 339 | Confirmed | High | [Evidence](screenshots/03-03_samr_full_name_identification.png) |

## Assessment

The network evidence strongly corroborates the NetSupport alert. Malicious or unauthorized use is suspected (medium confidence), not independently established. Provisional severity: High. Escalation: Tier 2 / Incident Response. Initial access, process identity, authorization, command execution, exfiltration, persistence and wider scope remain unknown. The DNS lead vadusa.xyz is unverified.
