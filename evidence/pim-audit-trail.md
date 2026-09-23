# PIM Remediation: Entra Audit Trail

Exported from Entra ID audit logs and sanitized (UPNs replaced by role, IPs and correlation IDs removed).
Times are UTC. This is the whole remediation, as the directory recorded it.

| Time (UTC) | Activity | Result | Actor | What it means |
| :--- | :--- | :--- | :--- | :--- |
| 03:48:34 | Onboarded resource to PIM | Success | admin | First PIM use put the subscription under PIM management. |
| 03:48:45 | Add eligible member to role in PIM requested (**permanent**) | **Failure** | admin | My script asked for eligibility with no expiry. The role policy forbids permanent eligibility (`ExpirationRule`). |
| 03:51:12 | Add eligible member to role in PIM requested (**time-bound**) | Success | admin | Re-requested with a 365-day eligibility. |
| 03:51:12 | Add eligible member to role in PIM completed (time-bound) | Success | admin | Eligible assignment provisioned. |
| 03:59:54 | Update role setting in PIM | Success | admin | Owner policy: 4h max activation, Azure MFA, justification required. |
| 04:00:57 | Update role setting in PIM | Success | admin | Approval turned on (no approver named — the mistake). |
| 04:11:59 | Add member to role requested (PIM activation) | Success | admin | Activation requested after standing Owner was removed. |
| 04:12:05 | Add member to role **approval requested** | Success | admin | Request went to an approver queue nothing could act on. |
| 04:38:40 | Update role setting in PIM | Success | **break-glass** | Emergency account fixed the policy. This is what break-glass exists for. |
| 04:43:44 | Add member to role **canceled** (PIM activation) | Success | admin | Stale request cleared; a policy change doesn't release a queued request. |
| 04:44:42 | Add member to role requested (PIM activation) | Success | admin | Re-requested with justification. |
| 04:44:50 | Add member to role **completed** (PIM activation) | Success | admin | Activated. Owner held for 4 hours, then it expires. |

**Elapsed: 56 minutes from first eligibility request to a working, time-boxed activation** — including one policy rejection and one self-inflicted approval lockout, both visible above.

**What this trail proves**
- Every privilege change is attributable: who, what, when, and whether it succeeded.
- The failure rows are the useful ones. `permanent` rejected, then `time-bound` accepted, is the ExpirationRule policy enforcing itself.
- The 04:38 row is the break-glass account earning its existence, and it's the reason the lockout was a 5-minute detour instead of a support ticket.
