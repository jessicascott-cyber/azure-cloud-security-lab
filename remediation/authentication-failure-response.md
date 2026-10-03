# Remediation — Authentication Failure Response

## Purpose

This document outlines the recommended SOC response when repeated authentication failures are detected in Microsoft Entra ID.

The goal is to determine whether the activity is normal user behavior, a credential issue, or potentially unauthorized account activity.

## Response Workflow

### 1. Validate the Alert

Confirm that the detection is based on actual Microsoft Entra sign-in events.

Review:

- User account
- Number of failed attempts
- Time of attempts
- Error code
- Authentication method
- Application
- Source IP address
- Location
- Device
- Browser

### 2. Determine Whether the Activity Is Expected

The analyst should determine whether the user recognizes the activity.

Possible legitimate causes include:

- Incorrect password
- Recently changed password
- Forgotten password
- Outdated saved credentials
- Password manager using an old password
- Application using outdated credentials

If the activity is confirmed as legitimate, document the finding and close the alert.

### 3. Look for Successful Authentication

Review sign-in activity surrounding the failed attempts.

A successful authentication following multiple failures should receive additional attention, particularly when the source, location, or device is unexpected.

The analyst should determine:

- Was the successful login from the same source?
- Was the device expected?
- Was the location expected?
- Did the successful login occur immediately after the failures?
- Were there additional authentication events?

### 4. Check for Broader Activity

Determine whether the behavior is isolated to one account.

Search for:

- Other accounts with failures from the same source
- Multiple accounts targeted within a short period
- Similar authentication patterns
- Other suspicious sign-in activity

Multiple affected accounts may indicate a broader credential attack.

## 5. Containment

If unauthorized activity is suspected, follow organizational incident-response procedures.

Potential containment actions may include:

- Require a password reset
- Revoke active sessions
- Require additional authentication
- Block or investigate the source
- Temporarily restrict the affected account when appropriate
- Escalate the incident to the appropriate security team

Containment actions should be based on the organization's policies and the evidence collected during the investigation.

## 6. Strengthen Account Protection

Recommended security controls may include:

- Multifactor authentication (MFA)
- Conditional Access policies
- Strong password requirements
- Risk-based sign-in policies
- Account lockout protections
- Monitoring for repeated authentication failures

These controls can reduce the likelihood and impact of credential attacks.

## 7. Document the Investigation

The analyst should record:

- Incident ID
- Affected account
- Date and time
- Detection that triggered
- Authentication failure count
- Source information
- Investigation findings
- Actions taken
- Final disposition

For this lab, the related incident is:

**INC-001 — Repeated Authentication Failures**

## Lab-Specific Outcome

The authentication failures involving the fictional **Alex Morgan** account were intentionally generated as part of this controlled cybersecurity lab.

The activity was therefore classified as:

**Benign / Authorized Lab Activity**

No account containment or credential reset was required.

## Recommended Production Response

If the same detection occurred against a real user account and the activity could not be explained by the user, the SOC analyst should escalate the investigation and follow the organization's account-compromise procedures.

Potential actions could include credential reset, session revocation, stronger authentication requirements, and additional monitoring.

## Lessons Learned

This lab demonstrates that detecting repeated authentication failures is only the first step.

A SOC analyst must also:

**Detect → Validate → Investigate → Determine Risk → Respond → Document**

The final response should be based on evidence rather than automatically treating every failed login as an attack.
