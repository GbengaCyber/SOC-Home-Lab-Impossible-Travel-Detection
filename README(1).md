# SOC Home Lab — Impossible Travel Detection

> **Microsoft Sentinel · Entra ID · Defender XDR · KQL · MITRE ATT&CK**  
> Full detection engineering, incident investigation, containment, and remediation — documented end to end.

---

## Overview

This lab documents a complete impossible travel investigation built and executed in a Microsoft Sentinel home lab environment. The scope covers everything a SOC analyst would touch on this type of alert — writing the detection rule, simulating the attack, triaging the incident, correlating logs, performing OSINT on suspicious IPs, containing the account, and closing the incident with full documentation.

The goal wasn't just to fire an alert. It was to work through the full analyst workflow and understand the *why* behind each step — not just the mechanics.

---

## Skills Demonstrated

- KQL query writing for detection engineering (`serialize`, `prev()`, consecutive login analysis)
- Microsoft Sentinel analytics rule creation and tuning
- Incident triage and investigation in Microsoft Defender XDR
- Log correlation in Azure Log Analytics
- OSINT on suspicious IPs (AbuseIPDB)
- Account containment and remediation in Microsoft Entra ID
- Conditional Access policy configuration
- MITRE ATT&CK mapping
- Incident documentation and closure

---

## Repo Structure

```
soc-lab-impossible-travel/
│
├── README.md                          ← this file
├── detection/
│   └── impossible_travel.kql          ← the KQL analytics rule
├── investigation/
│   └── Impossible_Travel_Report.docx  ← full investigation writeup
└── screenshots/
    ├── 01_analytics_rule_general.png
    ├── 02_analytics_rule_settings.png
    ├── 03_vpn_connected.png
    ├── 04_signin_logs_full.png
    ├── 05_incidents_queue.png
    ├── 06_incident_35_detail.png
    ├── 07_signin_logs_both_ips.png
    ├── 08_abuseipdb_ip1.png
    ├── 09_abuseipdb_ip2.png
    ├── 10_account_disabled.png
    ├── 11_sessions_revoked.png
    ├── 12_conditional_access_block.png
    ├── 13_password_mfa_reset.png
    └── 14_incident_closed.png
```

---

## What is Impossible Travel?

Impossible travel fires when the same account logs in from two locations within a timeframe that makes physical travel between them impossible. It is one of the most reliable early indicators of account compromise — the attacker is authenticating from their own infrastructure while the legitimate user is somewhere else.

Experienced attackers sometimes use VPN exit nodes close to their target's location to reduce the geographic anomaly. This is why the detection rule also monitors **VPN flips** — a sudden change in the anonymized IP flag between two consecutive logins is a signal worth investigating even if the country appears the same.

---

## The Detection Rule

### Analytics Rule Configuration

| Setting | Value |
|---|---|
| Rule Name | Impossible Travel Detection |
| Severity | Medium |
| Run every | 1 hour (5 mins during lab testing) |
| Lookback window | Last 4 hours |
| Alert threshold | More than 0 results |
| Event grouping | All events into a single alert |
| Entity mapping | Account → UserPrincipalName, IP → IPAddress |
| MITRE Tactics | Initial Access, Defense Evasion |
| MITRE Techniques | T1078 — Valid Accounts, T1133 — External Remote Services |

### Screenshot — General Tab

<img width="900" height="400" alt="image" src="https://github.com/user-attachments/assets/3f92237c-aa19-4e69-946b-2998e7f88f0e" />


### Screenshot — Schedule & Entity Mapping

<img width="985" height="510" alt="image" src="https://github.com/user-attachments/assets/3e860f9a-d337-43c8-a197-c68beadc7a61" />

---

### KQL Detection Query

```kql
let TravelWindow = 4h;

SigninLogs
| where TimeGenerated >= ago(TravelWindow)
| where ResultType == 0
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    City    = tostring(LocationDetails.city),
    IsVPN   = iff(NetworkLocationDetails has "anonymizedIPAddress", true, false)
| where isnotempty(Country) and isnotempty(City)
| project UserPrincipalName, TimeGenerated, IPAddress, Country, City, IsVPN
| order by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend
    PrevUser    = prev(UserPrincipalName),
    PrevTime    = prev(TimeGenerated),
    PrevCountry = prev(Country),
    PrevCity    = prev(City),
    PrevIP      = prev(IPAddress),
    PrevIsVPN   = prev(IsVPN)
| where UserPrincipalName == PrevUser
| extend TimeDiff = TimeGenerated - PrevTime
| where TimeDiff between (0min .. TravelWindow)
| where Country != PrevCountry
    or City != PrevCity
    or IsVPN != PrevIsVPN
| project
    UserPrincipalName, PrevTime, TimeGenerated, TimeDiff,
    PrevCountry, PrevCity, PrevIP, PrevIsVPN,
    Country, City, IPAddress, IsVPN
| order by UserPrincipalName asc, TimeGenerated asc
```

**Logic breakdown:**

| Component | Purpose |
|---|---|
| `ResultType == 0` | Successful logins only — impossible travel is only meaningful if the attacker got in |
| `serialize` | Locks row order so `prev()` reliably references the previous login per user |
| `prev()` | Compares each login directly against the previous one from the same account |
| `IsVPN != PrevIsVPN` | Catches VPN flip pattern — attacker dropping VPN after recon to blend in with local traffic |

> *In a production environment this would be extended with Haversine distance calculation, weighted risk scoring, and ASN-based VPN enrichment. The query above covers the core detection logic. See Lab Notes at the bottom for full details.*

---

## Simulating the Attack

| Step | Action |
|---|---|
| 1 | Logged into test account from home network — established clean baseline login |
| 2 | Connected Surfshark VPN (WireGuard) to a US exit node |
| 3 | Logged into the same account again through the VPN |
| 4 | 11 minutes between the two logins — impossible travel window triggered |

### Screenshot — VPN Connected

<img width="1000" height="500 alt="image" src="https://github.com/user-attachments/assets/6871acf6-24b5-47bb-8ccb-da39a9f4003f" />

*Surfshark VPN connected to US exit node — IP masked, WireGuard protocol, connection active*

---

## The Alert

### Screenshot — Incidents Queue

<!-- Add screenshot: screenshots/05_incidents_queue.png -->
![Incidents Queue](screenshots/05_incidents_queue.png)
*Defender XDR incidents list — Impossible Travel Detection fired with Medium severity and Critical Asset tag*

### Screenshot — Incident 35 Full Detail

<img width="1200" height="800" alt="image" src="https://github.com/user-attachments/assets/9461d80f-2c74-4757-b73f-8d9a81cfcb5a" />

*Attack story showing 2 active alerts, activity window 11:35–11:46 AM, and incident graph with user connected to 2 IPs*

---

## The Investigation

### Sign-in Log Correlation — Full Account Activity

```kql
SigninLogs
| where UserPrincipalName == "[REDACTED]@[REDACTED-TENANT].onmicrosoft.com"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, AppDisplayName,
          IPAddress, Location, AuthenticationDetails, OperationName
| order by TimeGenerated desc
```

<!-- Add screenshot: screenshots/04_signin_logs_full.png -->
![SigninLogs Full](screenshots/04_signin_logs_full.png)
*All successful logins for the affected account — home network IP and both suspicious VPN IPs visible*

### Sign-in Log Correlation — Both Suspicious IPs

```kql
SigninLogs
| where UserPrincipalName == "[REDACTED]@[REDACTED-TENANT].onmicrosoft.com"
| where IPAddress in ("XXX.XXX.X.XX", "XXX.XXX.X.XX")
| where ResultType == 0
| project TimeGenerated, AppDisplayName, IPAddress, Location
| order by TimeGenerated desc
```

<!-- Add screenshot: screenshots/07_signin_logs_both_ips.png -->
![SigninLogs Both IPs](screenshots/07_signin_logs_both_ips.png)
*All apps accessed by both suspicious IPs — M365 Security portal access at 11:38 AM clearly visible*

---

### Attack Timeline

| Time | App | IP | Location | Significance |
|---|---|---|---|---|
| 11:24 AM | My Signins | [Home IP — Masked] | Home | Legitimate login — clean residential IP |
| 11:35 AM | My Apps | XXX.XXX.X.XX | US | First VPN login — 11 mins after home login |
| 11:38 AM | M365 Security & Compliance | XXX.XXX.X.XX | US | Security portal — **reconnaissance behavior** |
| 11:42 AM | My Apps | XXX.XXX.X.XX | US | Second IP surfaces — same /24 subnet, IP rotation |
| 11:43 AM | Azure Portal | XXX.XXX.X.XX | US | Pivot to Azure admin portal |
| 11:43 AM | Azure Portal | XXX.XXX.X.XX | US | Both IPs active concurrently — concurrent sessions |
| 1:30 PM | Azure Portal | XXX.XXX.X.XX | US | **Returned after containment — persistence attempt** |

---

### Key Findings

**IP rotation within the same /24 subnet**  
Both suspicious IPs sat in the same /24 block — a technique used to evade per-IP session tracking. I identified and blocked both rather than just the first one that appeared in the alert. Both confirmed malicious via AbuseIPDB.

**M365 Security & Compliance portal access**  
Three minutes after the initial VPN login, the attacker accessed Microsoft 365 Security and Compliance. This is reconnaissance behavior — profiling audit log settings, DLP policies, and monitoring configuration before escalating. This is a higher-risk indicator than standard data access.

**The attacker returned after containment**  
At 1:30 PM — after initial containment steps — the attacker came back using the same IP and reached Azure Portal again. This confirmed the attack was deliberate and persistent, and indicated either a token caching issue or a slight delay in session revocation propagation.

**No lateral movement detected**  
Audit logs reviewed for the full incident window. No new accounts created, no forwarding rules added, no app permissions modified, no exfiltration indicators. Attack appears to have been in early reconnaissance phase.

---

### OSINT — IP Reputation

<!-- Add screenshot: screenshots/08_abuseipdb_ip1.png -->
![AbuseIPDB IP1](screenshots/08_abuseipdb_ip1.png)
*AbuseIPDB — first suspicious IP (XXX.XXX.X.XX) — multiple prior reports, confirmed malicious*

<!-- Add screenshot: screenshots/09_abuseipdb_ip2.png -->
![AbuseIPDB IP2](screenshots/09_abuseipdb_ip2.png)
*AbuseIPDB — second suspicious IP (XXX.XXX.X.XX) — same hosting infrastructure, also flagged*

---

## Containment

| Action | Tool | Purpose |
|---|---|---|
| Disabled account | Entra ID | Cut off live access immediately |
| Marked as compromised | Identity Protection | Activates risk-based policies and mandatory remediation |
| Revoked all sessions | Entra ID | Kills all active tokens — forces full re-authentication |
| Blocked both IPs tenant-wide | Conditional Access — Named Locations | Prevents reuse against any other account in the tenant |
| Assigned incident | Defender XDR | Ownership and audit trail |

<!-- Add screenshot: screenshots/10_account_disabled.png -->
![Account Disabled](screenshots/10_account_disabled.png)
*Entra ID — account disabled and marked compromised in Identity Protection*

<!-- Add screenshot: screenshots/11_sessions_revoked.png -->
![Sessions Revoked](screenshots/11_sessions_revoked.png)
*All active sessions revoked — tokens invalidated across all apps*

<!-- Add screenshot: screenshots/12_conditional_access_block.png -->
![IP Block](screenshots/12_conditional_access_block.png)
*Conditional Access Named Locations — both IPs blocked tenant-wide*

---

## Remediation

| Action | Detail |
|---|---|
| Password reset | Full credential reset — previous password invalidated immediately |
| MFA reset | All methods cleared, fresh re-enrollment required — removes any attacker-registered authenticator app |
| Conditional Access | MFA enforced as baseline requirement for all cloud app sign-ins |
| Tenant-wide IP block | Both IPs permanently blocked across all users |
| Account restored | Re-enabled after reset — user notified and briefed |
| Active monitoring | Account monitored for 24 hours post-recovery |

<!-- Add screenshot: screenshots/13_password_mfa_reset.png -->
![Password MFA Reset](screenshots/13_password_mfa_reset.png)
*Password reset and MFA methods cleared in Entra ID*

<!-- Add screenshot: screenshots/14_incident_closed.png -->
![Incident Closed](screenshots/14_incident_closed.png)
*Incident closed as True Positive in Defender XDR with analyst notes*

---

## MITRE ATT&CK

| Tactic | Technique | ID | Observed |
|---|---|---|---|
| Initial Access | Valid Accounts — Cloud Accounts | T1078.004 | Attacker used stolen valid credentials to authenticate |
| Defense Evasion | Valid Accounts | T1078 | Commercial VPN and /24 IP rotation to evade detection |
| Discovery | Cloud Service Discovery | T1526 | M365 Security portal access — active environment recon |
| Persistence | External Remote Services | T1133 | Returned at 1:30 PM after containment — persistent access attempt |

---

## Incident Closure

| Field | Detail |
|---|---|
| Classification | **True Positive** |
| Root cause | External credential compromise |
| Scope | Single account — no lateral movement, no exfiltration |
| Summary | Stolen credentials used to authenticate from two VPN IPs in the same /24 subnet. Attacker accessed MyApps, Azure Portal, and M365 Security portal. Returned after initial containment. Full credential reset, MFA re-enrollment, tenant-wide IP block applied. Account restored under monitoring. |

---

## Recommendations

**Immediate**
- Enforce MFA as a hard baseline for all cloud app sign-ins — not just on risk-triggered events
- Run tenant-wide query to check if the same IP subnet targeted other accounts
- Enable account lockout after repeated failed authentication attempts

**Longer term**
- Extend the detection rule with **Haversine distance calculation** to catch same-country impossible travel
- Add **Named Locations** in Conditional Access to baseline expected regions per user group
- Integrate a **threat intelligence feed** to score IPs automatically on ingest
- Build a **Logic Apps playbook** for automated containment on high-confidence detections

---

## Lab Notes

This lab was built in a Microsoft Sentinel home lab using a dedicated test account. The impossible travel was simulated by logging in from a home network to establish a clean baseline, then connecting through a commercial VPN (Surfshark, WireGuard) to a US exit node and logging in again from the same account — generating real SigninLogs and a real Sentinel incident.

The KQL query is intentionally kept at a foundational level. I focused on understanding the core detection logic deeply — `serialize`, `prev()`, consecutive login comparison — rather than using a complex query I couldn't fully explain. The production-ready extensions I would add:

- Haversine distance scoring between GPS coordinates
- Weighted multi-signal risk scoring
- ASN-based VPN enrichment for providers that don't set the anonymized flag
- Automated Logic Apps response playbook

---

## Full Investigation Report

Complete write-up with full timeline, log evidence, observations, containment steps, and remediation:  
[`investigation/Impossible_Travel_Report.docx`](investigation/Impossible_Travel_Report.docx)

---

*Built as part of an ongoing SOC home lab series focused on detection engineering, incident response, and cloud security operations.*
