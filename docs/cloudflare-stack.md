# Cloudflare Stack Integration

## Agents SDK (Durable Objects)

**One Agent instance per engagement**, not per target and not per
operator session — keyed by an `engagementId`.

Responsibilities:
- Owns the `EngagementState` (see `langgraph-flow.md`) as durable storage;
  writes a checkpoint after every graph node.
- Owns the `ScopeGrant` for its engagement — this is the single source of
  truth the Sandbox network policy and every tool wrapper check against.
- Exposes a WebSocket to the operator for:
  - live finding stream as Validators confirm/reject
  - `interrupt()` resume decisions
  - `pause` / `kill` signal, checked by the graph before each node
- Maintains the append-only audit log (every tool call, every LLM call,
  every operator decision) as its own storage entries, independent of
  whatever LangGraph's own checkpoint holds — this is the compliance /
  liability record, so it shouldn't be reconstructable-only from graph
  state.
- Uses `schedule()` / alarms if an engagement needs to re-check a
  previously-confirmed finding later (e.g. "did the misconfig get fixed"
  follow-up), rather than building separate infra for that.

## Sandbox SDK

**One container per tool task**, destroyed immediately after — no
container is reused across subdomains or across recon → validation.

- Recon tools (subdomain enum, nmap-style scans, curl/httpx header
  checks) and validation PoCs run in identical Sandbox primitives; the
  difference between "recon" and "exploit validation" is which command
  is run and the non-destructive-only policy on the validation side, not
  a different execution path.
- Network egress from the container is restricted to hosts within the
  active `ScopeGrant` — enforced at the container network policy level,
  not only by an in-graph check, so a prompt-injected or buggy tool call
  can't reach anything off-scope even if it tries.
- Tool output is parsed into structured JSON (exit code, stdout, stderr,
  parsed fields where the tool supports machine-readable output, e.g.
  `nmap -oX`) before it reaches an LLM call — keeps classification
  reliable and cheap.
- No credentials or engagement secrets are baked into the container image;
  anything a tool needs is injected per-invocation and scrubbed from logs.

## AI Gateway

All model calls — from every LangGraph node — route through AI Gateway,
never directly to a provider SDK.

- **Model tiering by node type:**
  - Worker classification calls → fast/cheap tier
  - ExploitValidation judgment + Report synthesis → stronger tier
  - Tiering is a Gateway routing rule, so it can be tuned without
    touching graph code.
- **Caching:** identical (tool-output signature → classification) pairs
  are cached — high value here specifically because the same misconfig
  pattern often repeats across many subdomains of one target.
- **Fallback:** provider/model fallback on rate-limit or outage, so a
  long-running engagement doesn't stall on a transient provider issue.
- **Logging:** Gateway request logs are the "which model, which prompt,
  which response produced this finding" trail — used alongside, not
  instead of, the Agent's own audit log.
- **Spend controls:** per-engagement budget/rate limit configured at the
  Gateway level, so a runaway graph (e.g. re-fanning-out on a bug) has a
  hard ceiling independent of application logic.

## Why this split (not one runtime doing everything)

- Sandbox gives process/network isolation Durable Objects don't provide —
  DOs run your orchestration logic, not arbitrary shell tools.
- The Agent gives durability/resumability and a live channel to a human,
  which a stateless LangGraph deployment alone wouldn't have.
- AI Gateway centralizes cost/safety controls that would otherwise be
  scattered across every node's model call.
