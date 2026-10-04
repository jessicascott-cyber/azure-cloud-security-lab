# Azure Cloud Security & Identity Monitoring Lab

## Overview

This project is a hands-on cloud security lab designed to demonstrate identity monitoring, authentication investigation, and SOC detection capabilities using Microsoft Azure.

The lab uses **Microsoft Entra ID**, **Azure Log Analytics**, and **Kusto Query Language (KQL)** to investigate authentication activity and identify repeated failed sign-in attempts.

The project follows a SOC investigation workflow:

**Monitor → Detect → Investigate → Map → Respond → Document**

The goal is to demonstrate practical skills that can be applied to an entry-level **SOC Analyst, Cloud Security, or IT Security** role.

## Objectives

- Configure Microsoft Entra ID for identity and authentication monitoring
- Create and configure an Azure Log Analytics workspace
- Route Microsoft Entra sign-in and audit logs to Log Analytics
- Investigate authentication activity using Kusto Query Language (KQL)
- Identify repeated failed authentication attempts
- Develop a SOC detection for suspicious authentication patterns
- Map authentication activity to the MITRE ATT&CK framework
- Document investigation findings and recommended response actions
- Build a portfolio-ready cloud security monitoring workflow
  
 ## Technologies & Tools

- **Microsoft Azure**
- **Microsoft Entra ID**
- **Azure Log Analytics**
- **Kusto Query Language (KQL)**
- **MITRE ATT&CK**
- **GitHub**
  
  ## Lab Architecture

The lab uses Microsoft Entra ID to generate identity and authentication activity, which is collected through diagnostic settings and sent to Azure Log Analytics for investigation using KQL.

```text
Microsoft Entra ID
       │
       ▼
  Sign-in Logs
       │
       ▼
Diagnostic Settings
       │
       ▼
Azure Log Analytics
       │
       ▼
      KQL
       │
       ▼
SOC Investigation
       │
       ├── Detection
       ├── MITRE ATT&CK
       └── Remediation
```

## Security Scenario

The lab simulates a SOC investigation involving repeated failed authentication attempts against a Microsoft Entra ID account.

A controlled authentication failure pattern was generated in the lab to simulate suspicious login activity. The resulting sign-in events were reviewed to determine the authentication result, failure reason, timing, and user activity.

The investigation focused on identifying whether the activity represented a potential brute-force or credential-based attack and documenting appropriate response actions.

## Investigation & Detection

The investigation focused on identifying repeated authentication failures and determining whether the activity could indicate a brute-force or credential-based attack.

Microsoft Entra ID sign-in activity was reviewed for authentication results, failure codes, timestamps, and user activity. The primary failure condition investigated was error code **50126**, which indicates an invalid username or password.

A KQL detection was developed to identify accounts experiencing five or more failed authentication attempts within a 24-hour period.

### Detection Logic

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "50126"
| summarize
    FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by UserPrincipalName, IPAddress
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

The detection is designed to help identify authentication patterns that may require additional investigation.

> **Lab Note:** The authentication failures used in this project were intentionally generated as part of an authorized security lab exercise.

## MITRE ATT&CK Mapping

The authentication activity investigated in this lab was mapped to the MITRE ATT&CK framework to provide context for the observed behavior.

### T1110 — Brute Force

The repeated failed authentication attempts are consistent with behavior associated with **T1110: Brute Force**, a Credential Access technique.

In a real-world environment, repeated authentication failures could indicate password guessing, credential stuffing, or another credential-based attack. Additional investigation would be required to determine the specific attack type and whether the activity was malicious.

The detailed MITRE ATT&CK mapping is documented in:

[View T1110 Brute Force Mapping](mitre-mapping/T1110-brute-force.md)

## Response & Remediation

The recommended response process for repeated authentication failures includes validating the alert, reviewing the affected account, and determining whether the activity is legitimate or suspicious.

Recommended response actions include:

- Validate the authentication failures and review the affected account
- Review successful and failed sign-in activity for related suspicious behavior
- Determine whether the activity was caused by the legitimate user
- Reset the account password if compromise is suspected
- Require or strengthen multifactor authentication (MFA)
- Consider Conditional Access policies to reduce authentication risk
- Document the investigation and response actions
- Continue monitoring for additional suspicious authentication activity

The detailed response procedure is documented in:

[View Authentication Failure Response](remediation/authentication-failure-response.md)

## Project Documentation

The project documentation is organized into separate sections covering the investigation, detection logic, MITRE ATT&CK mapping, remediation process, and supporting evidence.

- [Investigation Report](investigations/INC-001-account-authentication.md)
- [Detection Logic](detections/repeated-authentication-failures.md)
- [MITRE ATT&CK Mapping](mitre-mapping/T1110-brute-force.md)
- [Authentication Failure Response](remediation/authentication-failure-response.md)
- [Evidence & Screenshots](evidence/README.md)

## Key Findings

- Microsoft Entra ID successfully recorded authentication activity for the lab environment.
- Failed authentication events returned error code **50126**, indicating invalid username or password.
- Repeated authentication failures can be an indicator of potential credential-based attacks.
- KQL can be used to identify and summarize repeated authentication failures for investigation.
- The observed activity was intentionally generated as part of an authorized lab exercise.
- The investigation workflow demonstrated how identity telemetry can support SOC detection and response activities.

## Lessons Learned & Next Steps

This lab demonstrated how cloud identity telemetry can be collected, investigated, and used to develop security detections.

Key lessons from the project include:

- Identity logs provide valuable visibility into authentication activity.
- Authentication failures should be evaluated in context rather than treated as automatic security incidents.
- KQL can be used to efficiently investigate and summarize authentication activity.
- Detection logic should balance identifying suspicious behavior with reducing false positives.
- MITRE ATT&CK provides useful context for connecting observed activity to known adversary techniques.

Future improvements to the lab include:

- Add additional authentication detections
- Implement Microsoft Entra MFA and Conditional Access policies
- Expand monitoring to additional Azure security logs
- Create additional KQL-based SOC investigations
- Add more simulated attack scenarios

## Disclaimer

This project was created in an authorized personal lab environment for educational and portfolio purposes. All authentication activity and security testing were intentionally generated and performed within the lab environment.
