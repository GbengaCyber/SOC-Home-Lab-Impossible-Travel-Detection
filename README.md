# SOC Home Lab — Impossible Travel Detection

**Platform:** Microsoft Sentinel · Entra ID · Defender XDR  
**Skill Level:** Beginner → Intermediate  
**Date:** March 2026

---

## What This Is

This is a hands-on SOC lab where I built an impossible travel detection rule from scratch in Microsoft Sentinel, simulated a real attack scenario to trigger it, and then worked through the full investigation and response flow the way a SOC analyst would on the job.

The goal wasn't just to get an alert to fire. I wanted to understand the full lifecycle — why the detection logic works, what the logs actually tell you, how to triage an incident without just clicking through tabs, and what good containment and remediation looks like.

---

## What I Did

1. Wrote a KQL scheduled analytics rule to detect impossible travel based on consecutive login comparison
2. Created a test account in Entra ID and simulated a compromise — logged in from Canada, then through a VPN from the US
3. Waited for Sentinel to fire the incident, then investigated it properly
4. Found two malicious IPs in the same /24 subnet — IP rotation technique — and checked both on AbuseIPDB
5. Noticed the attacker accessed the M365 Security portal — flagged this as recon behavior
6. Contained the account, revoked sessions, blocked both IPs tenant-wide, reset credentials and MFA
7. Documented everything

---

## Repo Structure

```
soc-lab-impossible-travel/
│
├── README.md                          ← you are here
│
├── detection/
│   └── impossible_travel.kql          ← the KQL analytics rule query
│
├── investigation/
│   └── Impossible_Travel_Report.docx  ← full investigation writeup
│
└── screenshots/
    ├── 01_analytics_rule_general.png
    ├── 02_analytics_rule_settings.png
    ├── 03_vpn_connected.png
    ├── 04_signin_logs_raw.png
    ├── 05_incidents_fired.png
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

## Detection Rule

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

### Screenshot — Rule General Tab

<!-- Replace the line below with your actual screenshot -->
![Analytics Rule General Tab](screenshots/01_analytics_rule_general.png)
*Sentinel analytics rule showing name, severity, MITRE tactics, and enabled status*

---

### Screenshot — Rule Schedule & Entity Mapping

<!-- Replace the line below with your actual screenshot -->
![Analytics Rule Schedule](screenshots/02_analytics_rule_settings.png)
*Rule frequency set to 1 hour, lookback 4 hours, entity mapping for Account and IP*

---

### The KQL Query

The query compares each user's consecutive logins by serializing the results and using `prev()` to look at the row above. If the country, city, or VPN status changed between two logins within the travel window — it flags it.

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

**Why each piece matters:**
- `ResultType == 0` — successful logins only. Impossible travel only matters if the attacker actually got in
- `serialize` — locks row order so `prev()` works reliably
- `prev()` — compares each login against the one before it for the same user
- `IsVPN != PrevIsVPN` — catches the VPN flip pattern where an attacker drops their VPN after recon to blend in with a local IP

> *In production I'd extend this with Haversine distance calculation, weighted risk scoring, and ASN-based VPN enrichment. The version above focuses on the core logic.*

---

## Simulating the Attack

| Step | Action |
|---|---|
| 1 | Logged into test account from home network in Canada — baseline legitimate login |
| 2 | Connected Surfshark VPN (WireGuard) to a US exit node |
| 3 | Logged into the same account again through the VPN |
| 4 | Two logins 11 minutes apart — impossible travel triggered |

### Screenshot — VPN Connected

<!-- Replace the line below with your actual screenshot -->
![VPN Connected](screenshots/03_vpn_connected.png)
*Surfshark VPN connected to US exit node showing IP, WireGuard protocol, and connection time*

---

## The Alert Fired

### Screenshot — Incidents Queue

<!-- Replace the line below with your actual screenshot -->
![Incidents Queue](screenshots/05_incidents_fired.png)
*Defender XDR incidents list showing Impossible Travel Detection fired — Medium severity, Critical Asset tag*

---

### Screenshot — Incident 35 Detail

<!-- Replace the line below with your actual screenshot -->
![Incident Detail](screenshots/06_incident_35_detail.png)
*Full incident view showing attack story, 2 active alerts, first/last activity timestamps, and incident graph with 2 IPs*

---

## Investigation

### Sign-in Log Analysis — Full Account Activity

```kql
SigninLogs
| where UserPrincipalName == "[REDACTED]@[REDACTED-TENANT].onmicrosoft.com"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, AppDisplayName,
          IPAddress, Location, AuthenticationDetails, OperationName
| order by TimeGenerated desc
```

<!-- Replace the line below with your actual screenshot -->
![SigninLogs Full](screenshots/04_signin_logs_raw.png)
*All successful logins for the affected account showing both the Canadian home IP and the two US VPN IPs*

---

### Sign-in Log Analysis — Both Suspicious IPs

```kql
SigninLogs
| where UserPrincipalName == "[REDACTED]@[REDACTED-TENANT].onmicrosoft.com"
| where IPAddress in ("145.223.7.19", "145.223.7.29")
| where ResultType == 0
| project TimeGenerated, AppDisplayName, IPAddress, Location
| order by TimeGenerated desc
```

<!-- Replace the line below with your actual screenshot -->
![SigninLogs Both IPs](screenshots/07_signin_logs_both_ips.png)
*Filtered results showing all apps accessed by both malicious IPs — including the M365 Security portal access at 11:38 AM*

---

### Attack Timeline

| Time | App | IP | Location | Significance |
|---|---|---|---|---|
| 11:24 AM | My Signins | [Home IPv6] | Canada | Legitimate — residential home network |
| 11:35 AM | My Apps | 145.223.7.19 | US | First VPN login — 11 mins after Canada |
| 11:38 AM | M365 Security & Compliance | 145.223.7.19 | US | Accessed security portal — recon |
| 11:42 AM | My Apps | 145.223.7.29 | US | Second IP — same /24 subnet |
| 11:43 AM | Azure Portal | 145.223.7.29 | US | Pivot to Azure admin portal |
| 11:43 AM | Azure Portal | 145.223.7.19 | US | Both IPs active concurrently |
| 1:30 PM | Azure Portal | 145.223.7.19 | US | Returned after containment — persistence |

### Key Findings

**Two IPs, same subnet**  
Both IPs — 145.223.7.19 and 145.223.7.29 — were in the same /24 range. IP rotation within the same subnet is used to evade per-IP session tracking. Both confirmed malicious on AbuseIPDB.

**M365 Security portal access**  
At 11:38 AM the attacker accessed Microsoft 365 Security and Compliance. This is recon behavior — checking audit log configs, DLP policies, and what monitoring is in place before escalating.

**Persistence attempt at 1:30 PM**  
The attacker returned after initial containment and reached Azure Portal again. Either session revocation had a delay or a cached token survived. Confirmed True Positive.

**No lateral movement**  
Audit logs reviewed for the full window — no new accounts created, no forwarding rules, no app permissions changed, no exfiltration indicators.

---

### OSINT — AbuseIPDB

<!-- Replace the line below with your actual screenshot -->
![AbuseIPDB IP1](screenshots/08_abuseipdb_ip1.png)
*AbuseIPDB report for 145.223.7.19 — reported multiple times, confirmed malicious*

<!-- Replace the line below with your actual screenshot -->
![AbuseIPDB IP2](screenshots/09_abuseipdb_ip2.png)
*AbuseIPDB report for 145.223.7.29 — same infrastructure, also flagged malicious*

---

## Containment

| Action | Tool | Why |
|---|---|---|
| Disabled account | Entra ID | Cut off live access immediately |
| Marked as compromised | Identity Protection | Triggers risk policies and mandatory remediation |
| Revoked all sessions | Entra ID | Kills active tokens — forces re-auth |
| Blocked both IPs tenant-wide | Conditional Access Named Locations | Prevents reuse against any other account |
| Assigned incident to self | Defender XDR | Incident ownership and audit trail |

<!-- Replace the line below with your actual screenshot -->
![Account Disabled](screenshots/10_account_disabled.png)
*Entra ID showing account disabled and marked compromised in Identity Protection*

<!-- Replace the line below with your actual screenshot -->
![Sessions Revoked](screenshots/11_sessions_revoked.png)
*Session revocation confirmation for the affected account*

<!-- Replace the line below with your actual screenshot -->
![IP Block](screenshots/12_conditional_access_block.png)
*Conditional Access Named Locations showing both IPs added to the tenant-wide block list*

---

## Remediation

| Action | Detail |
|---|---|
| Password reset | Full reset — previous password invalidated |
| MFA reset | All methods cleared, fresh re-enrollment required — removes any attacker-registered authenticator |
| Conditional Access | MFA enforced for all cloud apps, high-risk locations blocked |
| Tenant-wide IP block | Both IPs permanently blocked across all users |
| Account restored | Re-enabled after reset. User notified and briefed |
| Active monitoring | Account watched for 24 hours post-recovery |

<!-- Replace the line below with your actual screenshot -->
![Password MFA Reset](screenshots/13_password_mfa_reset.png)
*Password reset and MFA methods cleared in Entra ID*

<!-- Replace the line below with your actual screenshot -->
![Incident Closed](screenshots/14_incident_closed.png)
*Incident closed as True Positive with analyst notes in Defender XDR*

---

## MITRE ATT&CK

| Tactic | Technique | ID | What I saw |
|---|---|---|---|
| Initial Access | Valid Accounts — Cloud Accounts | T1078.004 | Attacker used stolen valid credentials |
| Defense Evasion | Valid Accounts | T1078 | VPN usage and IP rotation to avoid detection |
| Discovery | Cloud Service Discovery | T1526 | Accessed M365 Security portal — environment recon |
| Persistence | External Remote Services | T1133 | Returned at 1:30 PM after initial containment |

---

## Incident Closure

| Field | Detail |
|---|---|
| Classification | True Positive |
| Root cause | External credential compromise |
| Scope | Single account — no lateral movement, no exfiltration |
| Notes | Credential reset, MFA re-enrollment, tenant-wide IP block. Account restored under monitoring. |

---

## What I'd Add in Production

The query is intentionally simple — I focused on understanding the core logic rather than adding complexity I can't explain. In a real environment I'd extend it with:

- **Haversine distance calculation** — compute km between login coordinates to catch same-country impossible travel (e.g. NY to LA in 20 mins)
- **Weighted risk scoring** — assign points per signal and surface high-confidence alerts first
- **ASN enrichment** — some VPN providers don't trip the `anonymizedIPAddress` flag, so cross-referencing known VPN/cloud ASN lists adds coverage
- **Automated Logic Apps playbook** — session revocation and user notification automatically on high-confidence detections without waiting for analyst triage

---

## Tools Used

- Microsoft Sentinel
- Microsoft Defender XDR
- Microsoft Entra ID
- Azure Log Analytics + KQL
- AbuseIPDB (OSINT)
- Surfshark VPN (WireGuard)

---

## Full Write-up

Detailed investigation report with full timeline, observations, containment steps, and remediation notes:  
[`investigation/Impossible_Travel_Report.docx`](investigation/Impossible_Travel_Report.docx)
