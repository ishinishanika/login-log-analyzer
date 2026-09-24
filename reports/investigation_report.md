# Sample Login Investigation

## Scope

Analyzed the ten synthetic records in data/sample_logins.csv.

All timestamps are UTC. All ten records passed validation.

## Activity Summary

- Total events: 10
- Successful logins: 4
- Failed logins: 6
- Unique usernames: 3
- Unique source IPs: 3

## Evidence

| Time (UTC) | Observed activity |
|---|---|
| 2026-09-24 10:01:00–10:03:00 | Five failed logins against admin from 198.51.100.20 |
| 2026-09-24 10:04:00 | Successful admin login from the same IP |
| 2026-09-24 10:05:00–10:06:00 | One failed bob login followed by success from 203.0.113.30 |

## Detection Results

Two related alerts were generated:

1. Repeated login failures from 198.51.100.20.
2. Success after repeated failures for admin from that IP.

These alerts describe overlapping activity and should be reviewed
together, not automatically counted as two separate incidents.

The bob sequence did not meet the configured failure threshold.
This does not independently establish that it was legitimate.

## Assessment

The admin sequence is consistent with possible password guessing
followed by access. Legitimate password mistakes are also a possible
explanation.

The available records do not establish whether access was unauthorized.

## Recommended Investigation

If this were a real incident:

- Confirm the login with the account owner through a trusted channel.
- Review MFA results and device information.
- Examine account activity after the successful login.
- Look for related attempts involving other accounts or source IPs.
- Follow the organization's incident response process if evidence
  supports unauthorized access.

## Outcome

Requires further evidence.

This exercise demonstrates detection and initial analysis.
No actual compromise or containment action is established.