# LangGraph Flow

## State schema

```python
class Finding(TypedDict):
    id: str
    subdomain: str
    category: str            # e.g. "misconfigured_header", "ssrf", "xss"
    evidence: dict            # raw tool output, request/response snippets
    severity: str             # low / medium / high / critical
    status: str               # unverified / confirmed / false_positive / needs_human_review

class EngagementState(TypedDict):
    scope: ScopeGrant          # see scope-and-safety.md
    target_domain: str
    subdomains: list[str]
    findings: list[Finding]
    validated: list[Finding]
    phase: str                 # recon / aggregate / validate / report / halted
    report: str | None
```

`ScopeGrant` and every tool wrapper are defined once and imported by every
node — there is no path to a tool call that skips the scope check.

## Graph structure

```
Orchestrator
    │  Send() — one Worker task per subdomain batch
    ▼
Worker (parallel, N instances)
    │  candidate findings, status=unverified
    ▼
Aggregator
    │  dedupe by (subdomain, category, evidence signature)
    │  Send() — one Validator task per unique finding
    ▼
ExploitValidation (parallel, N instances)
    │  status → confirmed / false_positive / needs_human_review
    ▼
[conditional edge]
    ├─ any finding needs_human_review or severity >= high → interrupt()
    │      operator resumes with approve/reject per finding
    └─ else → continue
    ▼
Report
```

## Node responsibilities

**Orchestrator**
- Takes `target_domain` + `scope`.
- Runs (or delegates) subdomain enumeration as its own first tool call.
- Batches discovered subdomains (e.g. 10–20 per batch) and `Send()`s a
  Worker task per batch. Batch size, not one-subdomain-per-task, keeps
  container/LLM-call overhead reasonable.

**Worker**
- Given a batch of subdomains, runs recon tools in Sandbox:
  - port/service scan
  - HTTP header and TLS config check
  - lightweight passive checks for common misconfig signatures
- Classifies raw tool output into candidate `Finding`s via a cheap model
  (AI Gateway routes this to the fast tier).
- Does **not** attempt exploitation — recon only.

**Aggregator**
- Pure function, no LLM call: dedupes and merges Worker output.
- Emits one Validator task per unique candidate finding via `Send()`.

**ExploitValidation**
- Given one `Finding`, designs and runs a *non-destructive* confirmation
  check in a fresh Sandbox (e.g. a reflected-parameter probe for XSS, a
  benign SSRF callback check against a controlled listener, re-requesting
  headers to confirm the misconfig is live — never data exfiltration or
  write/destructive actions).
- Uses search to check the fingerprinted service/version against known
  CVEs when relevant, to enrich severity/confidence.
- Classifies result: `confirmed`, `false_positive`, or
  `needs_human_review` (ambiguous evidence, or the check itself would need
  to go further than the non-destructive policy allows).
- Uses the stronger model tier — this is the judgment-heavy step.

**Human interrupt gate**
- Any `needs_human_review` finding, or any `confirmed` finding at or above
  the engagement's severity threshold, pauses the graph
  (`langgraph-human-in-the-loop` interrupt pattern).
- Operator reviews via the Agent's WebSocket feed and resumes with a
  per-finding decision (approve into report / reject / request deeper
  but still non-destructive check).

**Report**
- Compiles `confirmed` findings (post-approval) into the report format
  (see `report-format.md`).
- `false_positive` and rejected findings are kept in the audit log but
  excluded from the report body.

## Fan-out choice

`Send()` is used for both fan-outs (Orchestrator→Worker,
Aggregator→Validator) instead of a static edge list, since the number of
subdomains and findings is only known at runtime — this is the standard
LangGraph map-reduce pattern.

## Checkpointing

Graph state checkpoints after every node into the owning Cloudflare
Agent's Durable Object storage, so a multi-hour engagement survives a
Worker restart/hibernation and resumes exactly where it left off.
