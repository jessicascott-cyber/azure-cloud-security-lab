# MITRE ATT&CK Mapping — T1110 Brute Force

## Technique

**MITRE ATT&CK ID:** T1110

**Technique Name:** Brute Force

**Tactic:** Credential Access

## Description

T1110 — Brute Force covers attempts to gain access to accounts or systems by repeatedly trying credentials.

In this lab, repeated failed authentication attempts against the same Microsoft Entra ID account were used to simulate this type of behavior.

## Lab Activity

The fictional **Alex Morgan** account experienced multiple failed authentication attempts within a short period.

The Microsoft Entra sign-in events showed:

- Multiple authentication failures
- Error code **50126**
- Invalid username or password
- Password-based authentication
- Single-factor authentication

The activity was intentionally generated as part of this controlled cybersecurity lab.

## Why This Mapping Applies

Repeated authentication failures can be an indicator of credential-guessing activity.

In a real environment, a SOC analyst would investigate whether the attempts were:

- Normal user mistakes
- A forgotten or changed password
- An application using an outdated credential
- Password guessing
- Brute-force activity
- Another form of unauthorized authentication activity

Because the lab activity was intentionally generated, it should **not** be treated as an actual attack.

## Detection

The associated detection is:

**Repeated Authentication Failures**

The detection uses Microsoft Entra `SigninLogs` and looks for repeated authentication failures with error code `50126`.

The current detection threshold is:

**5 or more failed authentication attempts**

The detection groups activity by:

- `UserPrincipalName`
- `IPAddress`

## Related KQL

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
