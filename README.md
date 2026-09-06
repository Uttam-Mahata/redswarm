# redswarm

Autonomous cloud pen-testing / red-team swarm. A hierarchical multi-agent
pipeline that recons a target's attack surface, flags candidate
vulnerabilities, validates them with non-destructive proof-of-concept checks
in disposable sandboxes, and compiles an evidence-backed report — all under
an enforced authorization scope.

## Stack

| Concern | Tool |
|---|---|
| Agent reasoning / control flow | LangGraph (hierarchical graph, `Send` fan-out, `interrupt()` HITL) |
| Durable per-engagement runtime | Cloudflare Agents SDK (Durable Objects + SQLite storage) |
| Isolated tool execution | Cloudflare Sandbox SDK (network-scoped containers) |
| LLM routing / caching / audit | Cloudflare AI Gateway (model tiering, response caching) |
| External recon data | Subfinder, nmap, httpx (inside Sandbox containers) |

## Architecture

```
Operator
  │  POST /engagements  (scope grant + target)
  ▼
Cloudflare Worker (src/index.ts)
  │  routes by engagement_id
  ▼
EngagementAgent (Durable Object — src/agent/engagement-agent.ts)
  │  - Validates ScopeGrant
  │  - Owns audit log (DO SQLite, independent of graph state)
  │  - Operator WebSocket (pause/kill/resume/live findings)
  │  - Runs LangGraph graph
  ▼
LangGraph Graph (src/graph/index.ts)
  │
  ├─ Orchestrator → subdomain enum → Send() batches → Worker (parallel)
  ├─ Worker → port scan + header probe in Sandbox → LLM classify (fast tier)
  ├─ Aggregator → dedup → Send() per finding → ExploitValidation (parallel)
  ├─ ExploitValidation → non-destructive PoC in Sandbox → LLM judge (strong tier)
  ├─ HumanInterruptGate → interrupt() for high-severity / ambiguous findings
  └─ Report → JSON artifact + Markdown summary (strong tier)
              │
              ├─ AI Gateway (all LLM calls — routing, caching, audit)
              └─ ReconSandbox (all tool calls — scoped network egress)
```

## Project Structure

```
redswarm/
├── src/
│   ├── index.ts                     # Worker entrypoint — routes to DO
│   ├── types/index.ts               # Canonical types: ScopeGrant, Finding, EngagementState
│   ├── agent/
│   │   └── engagement-agent.ts      # EngagementAgent Durable Object
│   ├── graph/
│   │   ├── index.ts                 # Graph wiring (nodes + edges)
│   │   ├── state.ts                 # LangGraph state schema with reducers
│   │   └── nodes/
│   │       ├── orchestrator.ts      # Subdomain enum + batch fan-out
│   │       ├── worker.ts            # Recon tools + cheap LLM classification
│   │       ├── aggregator.ts        # Dedup + validator fan-out (pure function)
│   │       ├── exploit-validation.ts # Non-destructive PoC + strong LLM judgment
│   │       └── report.ts            # JSON artifact + Markdown synthesis
│   ├── tools/
│   │   ├── scope-check.ts           # Scope enforcement (called by every tool)
│   │   └── ai-gateway.ts            # AI Gateway client (model tiering + caching)
│   └── sandbox/
│       └── recon-sandbox.ts         # Cloudflare Sandbox SDK wrapper
├── sandbox/
│   └── Dockerfile                   # Container image (nmap, curl, subfinder, httpx)
├── docs/                            # Design docs
├── wrangler.jsonc                   # Cloudflare config (DO, Sandbox, bindings)
├── package.json
└── tsconfig.json
```

## Getting Started

### Prerequisites

- Node.js 20+
- Cloudflare account with Workers, Durable Objects, Containers, and AI Gateway enabled
- OpenAI API key

### Local Development

```bash
# Install dependencies
npm install

# Copy env vars template
cp .dev.vars.example .dev.vars
# Edit .dev.vars with your credentials

# Start local dev server (requires Docker for Sandbox containers)
npm run dev
```

### Create an Engagement

```bash
curl -X POST http://localhost:8787/engagements \
  -H "Content-Type: application/json" \
  -d '{
    "scope": {
      "engagement_id": "eng-001",
      "authorized_by": "security-team",
      "domains": ["example.com"],
      "ip_ranges": [],
      "excluded": ["admin.example.com"],
      "max_severity_auto_report": "high",
      "allow_active_probing": true,
      "expires_at": "2026-12-31T23:59:59Z"
    },
    "target_domain": "example.com"
  }'
```

### Connect as Operator

```javascript
// WebSocket connection for live findings + control
const ws = new WebSocket('ws://localhost:8787/engagements/eng-001/ws');

ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  if (msg.type === 'finding') console.log('New finding:', msg.finding);
  if (msg.type === 'interrupt') {
    // Review findings and resume
    ws.send(JSON.stringify({
      type: 'resume',
      finding_id: msg.findings[0].id,
      decision: 'approve'  // or 'reject' | 'deeper'
    }));
  }
  if (msg.type === 'report_ready') console.log('Report:', msg.report_md);
};
```

### Deploy

```bash
npm run deploy
```

## Safety Guarantees

redswarm never runs against a target without an explicit, structured `ScopeGrant`.
This is enforced at **three layers** (not just in prompts):

1. **Sandbox network egress** — container allowlist built from `ScopeGrant.domains` and `ip_ranges`. A prompt-injected tool call can't reach out-of-scope hosts even if it tries.
2. **Tool wrapper scope check** — every tool call passes through `scopeCheck()` before dispatching to a Sandbox. Failures are logged, non-silent errors.
3. **Agent kill switch** — operator can pause/kill at any time over WebSocket. The graph checks this before every node.

Exploit validation is **confirmation-only, never full exploitation**:
- ✅ Reflected-parameter probes, benign SSRF callbacks against a controlled listener, re-requesting headers
- ❌ Data exfiltration, write/delete/modify actions, lateral movement, credential use, DoS

## Docs

- [`docs/architecture.md`](docs/architecture.md) — system overview, component responsibilities
- [`docs/langgraph-flow.md`](docs/langgraph-flow.md) — graph structure, state schema, node behavior
- [`docs/cloudflare-stack.md`](docs/cloudflare-stack.md) — Agent/Sandbox/AI Gateway integration details
- [`docs/scope-and-safety.md`](docs/scope-and-safety.md) — authorization model, guardrails, non-negotiables
- [`docs/report-format.md`](docs/report-format.md) — output report structure
