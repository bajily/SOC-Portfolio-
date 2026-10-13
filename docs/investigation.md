# Authentication triage walkthrough

## Scenario and evidence

This is a **synthetic lab exercise**. In `samples/auth_events.csv`, `192.0.2.10` generates five failed logins for `analyst` between 09:00:00 and 09:01:20 UTC, followed by a successful login at 09:02:00 UTC. A separate successful login from `198.51.100.20` does not trigger a finding.

## Interpretation

The sequence could reflect password guessing followed by valid credentials, but it could also reflect an authorized user correcting a forgotten password. The rule raises priority for investigation; it does not establish compromise.

## Investigation checklist

1. Confirm timestamp normalization and the identity-provider event meaning.
2. Compare the source with the user's normal networks and recent activity.
3. Check MFA outcomes, device information, session creation, and post-login actions.
4. Look for similar failures across accounts or from multiple IP addresses.
5. Record evidence and escalate according to the organization's incident-response process.

## Example analyst conclusion

**Status:** requires investigation. **Confidence:** limited to authentication-event evidence. **Next step:** correlate with identity-provider and endpoint logs before deciding whether containment is necessary.

This repository demonstrates a reproducible investigation method, not a claim of real incident-response experience or a report about a real person.
