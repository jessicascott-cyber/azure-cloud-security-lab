# Evidence

This folder contains sanitized screenshots and supporting evidence from the Microsoft Azure and Microsoft Entra ID cloud security lab.

## Evidence Purpose

The evidence supports the investigation documented in:

`investigations/INC-001-account-authentication.md`

The investigation focuses on repeated authentication failures involving the fictional **Alex Morgan** test account.

## Planned Evidence

The following evidence will be included as the lab develops:

| Evidence | Purpose |
|---|---|
| Successful sign-in screenshot | Demonstrates normal authentication activity |
| Failed sign-in screenshot | Demonstrates authentication failure |
| Sign-in log pattern | Shows multiple authentication failures |
| Diagnostic setting | Demonstrates Entra logs being routed to Log Analytics |
| Log Analytics query | Demonstrates KQL-based investigation |
| Detection results | Demonstrates the detection logic identifying the activity |

## Data Sanitization

Screenshots uploaded to this public repository should be reviewed before publication.

Sensitive or unnecessary information should be removed or obscured, including:

- IP addresses
- Tenant IDs
- Request IDs
- Correlation IDs
- Subscription IDs
- Access tokens
- Passwords
- Personal information
- Other security-sensitive identifiers

The purpose of the screenshots is to demonstrate the investigation process, not to expose unnecessary environment information.

## Lab Context

The authentication failures documented in this project were intentionally generated against a fictional test account as part of an authorized cybersecurity lab.

The activity does not represent an actual security incident.

## Log Analytics Evidence

The Microsoft Entra diagnostic setting `Entra-SOC-Monitoring` has been configured to send sign-in and audit logs to the `law-soc-cloud` Log Analytics workspace.

Log Analytics evidence will be added after the Entra logs become available in the workspace.
