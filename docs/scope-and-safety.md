# Scope and Safety

redswarm actively scans and probes live systems. This doc is the
non-negotiable part of the design — everything else can be refined later,
this can't be skipped.

## Scope grant

Every engagement requires an explicit `ScopeGrant` before the graph runs:

```python
class ScopeGrant(TypedDict):
    engagement_id: str
    authorized_by: str          # who approved this engagement
    domains: list[str]          # exact domains/subdomains in scope
    ip_ranges: list[str]        # CIDR ranges in scope, if any
    excluded: list[str]         # explicit carve-outs within an in-scope range
    max_severity_auto_report: str   # findings above this always need human sign-off
    allow_active_probing: bool  # false = passive recon only
    expires_at: datetime        # engagements are time-boxed, not indefinite
```

- No `target_domain` is ever accepted without a matching `ScopeGrant`.
- Any subdomain discovered during recon that resolves outside the
  granted `domains`/`ip_ranges` (e.g. a CDN-fronted third party, a
  different company's infra sharing IP space) is **dropped from the
  pipeline**, not flagged as a finding, not scanned further.
- `expires_at` is enforced by the Agent — an engagement past its window
  refuses to schedule new tool calls, even if resumed.

## Enforcement points (defense in depth — not just a prompt rule)

1. **Sandbox network policy** — container egress allowlist built from
   the active `ScopeGrant`. This is the real backstop: even a
   compromised/prompt-injected tool call can't reach out-of-scope hosts.
2. **Tool wrapper check** — every tool invocation (recon or validation)
   checks the target against `ScopeGrant` before dispatching to a
   Sandbox, and rejects with a logged, non-silent error otherwise.
3. **Agent-level kill switch** — operator can pause/kill an engagement
   at any time over the WebSocket; the graph checks this flag before
   every node, not just at start.
4. **No prompt-only guardrails** — scope, severity gating, and the
   non-destructive policy are code-enforced conditions on graph edges
   and tool wrappers, not instructions the model is asked to follow.

## Exploit validation policy

ExploitValidation nodes are **confirmation-only**, never full exploitation:

- Allowed: reflected-parameter probes, benign SSRF callback checks
  against a controlled listener, re-requesting to confirm a
  misconfiguration is live, reading response headers/metadata.
- Never allowed: data exfiltration, write/modify/delete actions against
  the target, lateral movement, credential use/brute force, denial of
  service, anything that persists a change on the target.
- If confirming a finding would require crossing that line, the node
  classifies it `needs_human_review` with a note on what further step
  *would* confirm it — the human decides whether and how to proceed
  manually, outside the automated pipeline.

## Human-in-the-loop gates

- Any `needs_human_review` finding.
- Any `confirmed` finding at or above `max_severity_auto_report`.
- Engagement start itself, if `allow_active_probing` is false-by-default
  and being flipped true for this run — active probing is an explicit
  per-engagement opt-in, not a default.

## Audit trail

Every tool call, every LLM call, every scope check (pass or reject),
and every human decision is appended to the Agent's audit log with a
timestamp and the responsible node. This log is the deliverable that
makes the engagement defensible after the fact — it should be exportable
as-is alongside the final report.

## Out of scope for this project (by design)

- No autonomous "full kill chain" exploitation (initial access → lateral
  movement → persistence). This is recon + confirmation + reporting.
- No capability to target infrastructure without a scope grant record,
  even for "testing the tool itself" — use a lab environment you own for
  that, with its own scope grant.
