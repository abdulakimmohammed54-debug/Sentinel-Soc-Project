# Microsoft Sentinel SOC Lab: Brute-Force & Encoded PowerShell Detection and Automated Response

![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-SIEM-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1110%20%7C%20T1059.001-red)
![Atomic Red Team](https://img.shields.io/badge/Atomic%20Red%20Team-Attack%20Simulation-orange)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

## Overview
This project demonstrates a complete, end-to-end SOC detection and response pipeline 
built in Microsoft Sentinel. Real-world attack techniques were simulated using Atomic 
Red Team, detected using custom KQL analytics rules aligned to MITRE ATT&CK, and 
responded to automatically via Logic App playbooks — replicating a production SOC workflow.

---

## Tools & Technologies
| Category | Tool |
|----------|------|
| SIEM | Microsoft Sentinel |
| Attack Simulation | Atomic Red Team |
| Query Language | KQL (Kusto Query Language) |
| Automation | Azure Logic Apps |
| Framework | MITRE ATT&CK |
| Cloud Platform | Microsoft Azure |

---

## Attack Scenarios & MITRE ATT&CK Mapping
| Attack Type | Tactic | Technique ID | Description |
|-------------|--------|--------------|-------------|
| Brute Force | Credential Access | T1110 | Repeated failed login attempts to gain unauthorized access |
| System Information Discovery | Discovery | T1082 | Executed system enumeration commands to gather OS, hardware, and network details from a compromised host |

---

## Project Architecture
```plaintext
+-------------------------------+
|  Atomic Red Team              |
|  Attack Simulation            |
|  (T1110 & T1059.001)          |
+-------------------------------+
                ↓
+-------------------------------+
|  Windows VM                   |
|  Log Generation               |
|  (Event ID 4625 & 4688)       |
+-------------------------------+
                ↓
+-------------------------------+
|  Log Analytics Workspace      |
|  Log Ingestion & Storage      |
+-------------------------------+
                ↓
+-------------------------------+
|  Microsoft Sentinel           |
|  KQL Analytics Rules          |
|  Threat Detection             |
+-------------------------------+
                ↓
+-------------------------------+
|  Incident Created             |
|  Automatically Prioritized    |
+-------------------------------+
                ↓
+-------------------------------+
|  Logic App Playbook           |
|  Automated Response           |
+-------------------------------+
          ↓           ↓        ↓
  +-----------+ +----------+ +----------+
  | Add       | | Send     | | Enrich   |
  | Comment   | | Email    | | Incident |
  | to        | | Alert    | | with     |
  | Incident  | | to SOC   | | Details  |
  +-----------+ +----------+ +----------+
                ↓
+-------------------------------+
|  Analyst Investigation        |
|  & Incident Review            |
+-------------------------------+
```
---

## Attack Simulation
Atomic Red Team was used to execute real adversary techniques and generate 
authentic telemetry for detection validation.

### Brute Force (T1110)
- Simulated repeated failed authentication attempts against a target system
- Generated Windows Security Event logs (Event ID 4625)
- Validated that Sentinel detected abnormal login failure patterns

### System Information Discovery (T1082)
- Simulated post-compromise reconnaissance by executing system enumeration commands on a target Windows host
- Generated Windows Security Event logs (Event ID 4688)
- Validated that Sentinel detected suspicious discovery activity using process creation logs
---

## Detection — KQL Analytics Rules

### Brute Force Detection
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 10
| project TimeGenerated, Account, IpAddress, FailedAttempts
```

### System Information Discovery
```kql
SecurityEvent
| where EventID == 4799
| where CallerProcessName has "WmiPrvSE"
| project
    TimeGenerated,
    Computer,
    SubjectUserName,
    TargetUserName,
    CallerProcessName
| order by TimeGenerated desc
```

---

## Automated Response — Logic App Playbooks
Upon incident creation, the following automated response actions were triggered:

- **Incident Comment** — Automatically adds investigation context to the incident
- **Email Notification** — Sends alert to SOC team with incident details
- **Incident Enrichment** — Tags severity, maps to ATT&CK technique, 
  and appends relevant entity data

---

## End-to-End Workflow
1. Atomic Red Team executes simulated attack technique
2. Target system generates logs captured by Log Analytics Workspace
3. KQL analytics rule detects suspicious behavior and triggers alert
4. Microsoft Sentinel automatically creates and prioritizes incident
5. Logic App playbook fires automated response actions:
   - Adds comment with context to incident
   - Sends email notification to SOC
   - Enriches incident with entity and technique data
6. Analyst reviews enriched incident and conducts investigation

---

## Screenshots
| # | Description |
|---|-------------|
| 1 | KQL analytics rule configuration |
| 2 | Atomic Red Team attack execution |
| 3 | Incident created in Microsoft Sentinel |
| 4 | Playbook workflow in Logic Apps |
| 5 | Automated comment added to incident |
| 6 | Email alert received by SOC |

## Screenshots
📁 [View All Screenshots](Screenshots/)

---

## Demo Video
▶️ https://www.youtube.com/watch?v=QPKETkrW8Vo

---

## Key Skills Demonstrated
- **Detection Engineering** — Built custom KQL rules with tuned thresholds 
  to reduce false positives
- **Adversarial Simulation** — Executed MITRE ATT&CK techniques using 
  Atomic Red Team to generate realistic attack telemetry
- **Incident Response Automation** — Designed Logic App playbooks to 
  automate SOC triage workflows
- **MITRE ATT&CK Alignment** — Mapped all detections and simulations 
  to industry-standard threat framework
- **End-to-End Validation** — Confirmed full pipeline coverage from 
  attack execution to automated response

---

## Author
**Abdulhakim Heyder**
Cybersecurity Professional | Aspiring SOC Analyst
https://www.linkedin.com/in/abdulhakim-heyder-20469a221/(#) | [GitHub](#)
