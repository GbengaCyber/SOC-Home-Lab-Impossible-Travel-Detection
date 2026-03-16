# SOC Home Lab — Impossible Travel Detection

> **Microsoft Sentinel · Entra ID · Defender XDR · KQL · MITRE ATT&CK**  
> Full detection engineering, incident investigation, containment, and remediation — documented end to end.


## Overview

This lab documents a complete impossible travel investigation built and executed in a Microsoft Sentinel home lab environment. The scope covers everything a SOC analyst would touch on this type of alert, writing the detection rule, simulating the attack, triaging the incident, correlating logs, performing OSINT on suspicious IPs, containing the account, and closing the incident with full documentation.

The goal wasn't just to fire an alert. It was to work through the full analyst workflow and understand the scope behind each step, not just the mechanics.

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

## What is Impossible Travel?

Impossible travel fires when the same account logs in from two locations within a timeframe that makes physical travel between them impossible. It is one of the most reliable early indicators of account compromise — the attacker is authenticating from their own infrastructure while the legitimate user is somewhere else.

Experienced attackers sometimes use VPN exit nodes close to their target's location to reduce the geographic anomaly. This is why the detection rule also monitors **VPN flips**  a sudden change in the anonymized IP flag between two consecutive logins is a signal worth investigating even if the country appears the same.

---

## The Detection Rule

### Analytics Rule Configuration

** Setting | Value 

| Rule Name | Impossible Travel Detection |
| Severity | Medium |
| Run every | 1 hour (5 mins during lab testing) |
| Lookback window | Last 4 hours |
| Alert threshold | More than 0 results |
| Event grouping | All events into a single alert |
| Entity mapping | Account → UserPrincipalName, IP → IPAddress |
| MITRE Tactics | Initial Access, Defense Evasion |
| MITRE Techniques | T1078 — Valid Accounts, T1133 — External Remote Services |

### General Tab

<img width="900" height="400" alt="image" src="https://github.com/user-attachments/assets/3f92237c-aa19-4e69-946b-2998e7f88f0e" />

---
### Schedule & Entity Mapping

<img width="800" height="400" alt="image" src="https://github.com/user-attachments/assets/71027c2f-9582-4d90-aed7-f3fa4d46afe0" />

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

Component - Purpose 

| `ResultType == 0` | Successful logins only — impossible travel is only meaningful if the attacker got in |
| `serialize` | Locks row order so `prev()` reliably references the previous login per user |
| `prev()` | Compares each login directly against the previous one from the same account |
| `IsVPN != PrevIsVPN` | Catches VPN flip pattern — attacker dropping VPN after recon to blend in with local traffic |

> *In a production environment this would be extended with Haversine distance calculation, weighted risk scoring, and ASN-based VPN enrichment. The query above covers the core detection logic. See Lab Notes at the bottom for full details.*

---
## Simulating the Attack

 Step - Action 

.  Logged into test account from home network — established clean baseline login 
.  Connected Surfshark VPN (WireGuard) to a US exit node 
.  Logged into the same account again through the VPN 
.  11 minutes between the two logins — impossible travel window triggered 

### VPN Connected

<img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/1404d238-c66b-4e21-b24c-e8c77e6dd09e" />

*Surfshark VPN connected to US exit node — IP masked, WireGuard protocol, connection active*

---

## The Alert

### Incidents Queue

<img width="700" height="256" alt="image" src="https://github.com/user-attachments/assets/444057d5-a2d0-4a70-b172-0a7bf3054ef0" />

*Defender XDR incidents list — Impossible Travel Detection fired with Medium severity and Critical Asset tag*

### Incident 35 Full Detail

<img width="1000" height="400" alt="image" src="https://github.com/user-attachments/assets/9461d80f-2c74-4757-b73f-8d9a81cfcb5a" />

*Attack story showing 2 active alerts, activity window 11:35–11:46 AM, and incident graph with user connected to 2 IPs*

---

## The Investigation

### Sign-in Log Correlation — Full Account Activity

```kql
SigninLogs
| where UserPrincipalName == "gbXXXX@onmicrosoft.com"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, AppDisplayName,
          IPAddress, Location, AuthenticationDetails, OperationName
| order by TimeGenerated desc
```
<img width="800" height="500" alt="image" src="https://github.com/user-attachments/assets/2332c72d-2ed8-4b36-91d0-ff879e71f55d" />

*All successful logins for the affected account — home network IP and both suspicious VPN IPs visible*

### Sign-in Log Correlation — Both Suspicious IPs

```kql
SigninLogs
| where UserPrincipalName == "gbXXXX@onmicrosoft.com"
| where IPAddress in ("145.223.7.29", "145.223.7.19")
| where ResultType == 0
| project TimeGenerated, AppDisplayName, IPAddress, Location
| order by TimeGenerated desc
```

<img width="800" height="700" alt="image" src="https://github.com/user-attachments/assets/4145e300-57d7-4aa7-958a-eeda1d8dcace" />

*All apps accessed by both suspicious IPs — M365 Security portal access at 11:38 AM clearly visible*

---

### Attack Timeline

. 11:24 AM - My Signins - [Home IP — Masked] - Home - Legitimate login — clean residential IP 
. 11:35 AM - My Apps - 145.223.7.19 - US - First VPN login — 11 mins after home login 
. 11:38 AM - M365 Security & Compliance - 145.223.7.19 - US - Security portal — **reconnaissance behavior** |
. 11:42 AM - My Apps - 145.223.7.29 - US - Second IP surfaces — same /24 subnet, IP rotation 
. 11:43 AM - Azure Portal - 145.223.7.29 - US - Pivot to Azure admin portal 
. 11:43 AM - Azure Portal - 145.223.7.19 - US - Both IPs active concurrently — concurrent sessions 
. 1:30 PM - Azure Portal - 145.223.7.19 - US - **Returned after containment — persistence attempt** 

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

<img width="750" height="400" alt="image" src="https://github.com/user-attachments/assets/88cff965-1e48-4cf0-93c3-be78803937df" />

*AbuseIPDB — first suspicious IP (145.223.7.19) — multiple prior reports, confirmed malicious*

---

## Containment

| Action | Tool | Purpose |

- Disabled account | Entra ID | Cut off live access immediately |
- Marked as compromised | Identity Protection | Activates risk-based policies and mandatory remediation |
-  Revoked all sessions | Entra ID | Kills all active tokens — forces full re-authentication |
- locked both IPs tenant-wide | Conditional Access — Named Locations | Prevents reuse against any other account in the tenant |
-  ssigned incident | Defender XDR | Ownership and audit trail |

<img width="885" height="398" alt="image" src="https://github.com/user-attachments/assets/7daa3dda-ae61-4cc3-b131-dc9e1007edd3" />

*Entra ID — account disabled and marked compromised in Identity Protection*

---
<img width="700" height="350" alt="image" src="https://github.com/user-attachments/assets/78848f0f-1350-4eb8-b10f-560deab3d7f9" />

*XDR — Blocked IPs accross Tenant*


*All active sessions revoked — tokens invalidated across all apps*

<img width="850" height="380" alt="image" src="https://github.com/user-attachments/assets/50d8848a-7dc7-4e72-aaa0-1a2aaf1687ba" />

*Conditional Access Named Locations — both IPs blocked tenant-wide*

---

## Remediation

| Action | Detail |

| Password reset | Full credential reset — previous password invalidated immediately 
| MFA reset | All methods cleared, fresh re-enrollment required — removes any attacker-registered authenticator app 
| Conditional Access | MFA enforced as baseline requirement for all cloud app sign-ins 
| Tenant-wide IP block | Both IPs permanently blocked across all users 
| Account restored | Re-enabled after reset — user notified and briefed 
| Active monitoring | Account monitored for 24 hours post-recovery 

<img width="1000" height="530" alt="image" src="https://github.com/user-attachments/assets/2c090b14-ed91-40ff-9eb7-a5f39d9b8375" />

---

## MITRE ATT&CK

| Tactic | Technique | ID | Observed |

| Initial Access | Valid Accounts — Cloud Accounts | T1078.004 | Attacker used stolen valid credentials to authenticate 
| Defense Evasion | Valid Accounts | T1078 | Commercial VPN and /24 IP rotation to evade detection 
| Discovery | Cloud Service Discovery | T1526 | M365 Security portal access — active environment recon 
| Persistence | External Remote Services | T1133 | Returned at 1:30 PM after containment — persistent access attempt 

---

## Incident Closure

| Classification | **True Positive** |
| Root cause | External credential compromise 
| Scope | Single account — no lateral movement, no exfiltration 
|  Summary | Stolen credentials used to authenticate from two VPN IPs in the same /24 subnet. Attacker accessed MyApps, Azure Portal, and M365 Security portal. Returned after initial containment. Full credential reset, MFA re-enrollment, tenant-wide IP block applied. Account restored under monitoring. |

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

This lab was built in a Microsoft Sentinel home lab using a dedicated account. The impossible travel was simulated by logging in from a home network to establish a clean baseline, then connecting through a commercial VPN (Surfshark, WireGuard) to a US exit node and logging in again from the same account — generating real SigninLogs and a real Sentinel incident.

The KQL query is intentionally kept at a foundational level. I focused on understanding the core detection logic deeply — `serialize`, `prev()`, consecutive login comparison. The production-ready extensions I would add:

- Haversine distance scoring between GPS coordinates
- Weighted multi-signal risk scoring
- ASN-based VPN enrichment for providers that don't set the anonymized flag
- Automated Logic Apps response playbook

---
*Built as part of an ongoing SOC home lab series focused on detection engineering, incident response, and cloud security operations.*
