# Architecture

## Overview

```
                         ┌─────────────────────────┐
                         │  Cloudflare Agent (DO)   │
                         │  one instance / engagement│
                         │  - scope, state, audit log│
                         │  - WebSocket to operator  │
                         └───────────┬──────────────┘
                                     │ drives
                                     ▼
                         ┌─────────────────────────┐
                         │      LangGraph graph      │
                         │  Orchestrator → Workers →  │
                         │  Aggregator → Validators → │
                         │  Report                    │
                         └───────────┬──────────────┘
                     tool calls      │      LLM calls
                    ┌────────────────┴───────────────┐
                    ▼                                 ▼
         ┌─────────────────────┐          ┌─────────────────────┐
         │ Cloudflare Sandbox    │          │   AI Gateway          │
         │ short-lived containers│          │  routing/cache/audit  │
         │ scoped egress only    │          └─────────────────────┘
         └─────────────────────┘
```

## Components

### Cloudflare Agent (Durable Object) — engagement runtime

One Agent instance per engagement (keyed by engagement ID, not target
domain, so re-testing the same target later is a fresh engagement).
Holds:

- `scope`: the authorization grant (see `scope-and-safety.md`)
- `state`: current LangGraph checkpoint (subdomains, findings, validated
  findings, phase)
- `auditLog`: append-only list of every tool call and LLM call made
- an operator WebSocket connection for live findings + pause/resume/kill

The Agent is what makes the engagement resumable — a scan that takes hours
can hibernate and wake on the next event without losing state, and an
operator can reconnect mid-run.

### LangGraph graph — reasoning and control flow

See `langgraph-flow.md`. Runs *inside* the Agent's request handling (the
Agent invokes the graph, checkpointing graph state into DO storage after
each node).

### Cloudflare Sandbox — isolated execution

Every recon tool call (subdomain enum, port scan, header probe) and every
exploit-validation PoC runs in its own short-lived Sandbox container:

- fresh container per task, destroyed after
- network egress restricted to the scoped target only
- structured stdout/stderr/exit-code capture, not raw text scraping

### AI Gateway — model routing, caching, audit

All LLM calls (classification, planning, report synthesis) go through AI
Gateway rather than directly to a provider:

- cheap/fast model for high-volume classification (e.g. "is this header
  misconfigured?")
- stronger model reserved for exploit-validation judgment and report
  synthesis
- response caching for repeated identical tool-output → classification
  calls (common across many subdomains with the same misconfig)
- gateway-level logs double as a "why did the model flag this" trail,
  independent of the Agent's own audit log

### Search — external grounding

Used by Worker/Validator nodes to look up CVEs for a fingerprinted
service/version, or confirm whether a flagged behavior is a known false
positive pattern, before it's promoted to a finding.

## Data flow summary

1. Operator submits `target_domain` + `scope` grant → Agent created.
2. Agent invokes LangGraph graph with initial state.
3. Orchestrator splits domain into recon batches → `Send()` to Workers.
4. Workers run tools in Sandboxes, tag candidate findings `unverified`.
5. Aggregator dedupes → fans out to ExploitValidation.
6. Validators run non-destructive PoC checks in fresh Sandboxes,
   classify `confirmed` / `false_positive` / `needs_human_review`.
7. Anything `needs_human_review` or above severity threshold triggers
   `interrupt()` — operator approves/rejects via the Agent's WebSocket.
8. Report node compiles confirmed findings into the final report.
9. Every step appends to the Agent's audit log.
