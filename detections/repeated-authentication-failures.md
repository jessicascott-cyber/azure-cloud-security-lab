# Detection — Repeated Authentication Failures

## Detection Overview

**Detection Name:** Repeated Authentication Failures

**Data Source:** Microsoft Entra ID Sign-in Logs

**Log Analytics Table:** `SigninLogs`

**Severity:** Medium

**MITRE ATT&CK:** T1110 — Brute Force

## Purpose

This detection identifies repeated failed authentication attempts against the same user account.

A high number of failed authentication attempts within a short period may indicate password guessing, credential attacks, or a user repeatedly entering incorrect credentials.

The detection should be investigated by a SOC analyst to determine whether the activity is legitimate or suspicious.

## Detection Logic

The detection looks for Microsoft Entra authentication failures with error code `50126`.

Error code `50126` indicates that the supplied username or password was invalid.

The detection groups failed authentication events by:

- User account
- Source IP address

An alert is generated when an account has five or more failed authentication attempts within the selected time period.

## KQL Query

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
