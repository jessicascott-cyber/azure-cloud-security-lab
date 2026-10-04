# Azure Cloud Security & Identity Monitoring Lab

## Overview

This project demonstrates a hands-on cloud security monitoring and identity investigation lab using Microsoft Azure, Microsoft Entra ID, Azure Log Analytics, and KQL.

The lab simulates a SOC analyst investigating repeated authentication failures against a test account and demonstrates the process of detection, investigation, MITRE ATT&CK mapping, and remediation.

## Objectives

- Configure Microsoft Entra ID monitoring
- Collect identity and authentication logs
- Configure Azure Log Analytics
- Investigate authentication activity using KQL
- Identify repeated failed authentication attempts
- Document a security investigation
- Map suspicious behavior to MITRE ATT&CK
- Develop a SOC detection
- Document recommended remediation actions

## Lab Architecture

```text
Microsoft Entra ID
       │
       │ Sign-in Logs
       ▼
Diagnostic Settings
       │
       ▼
Azure Log Analytics
       │
       │ KQL
       ▼
SOC Investigation
       │
       ├── Detection
       ├── MITRE ATT&CK
       └── Remediation
