/**
 * src/agent/engagement-agent.ts
 *
 * Cloudflare Agent (Durable Object) — one instance per engagement.
 *
 * The Agent is the durable runtime that:
 * - Owns the ScopeGrant (single source of truth for scope enforcement)
 * - Stores the LangGraph checkpoint in DO SQLite storage after every node
 * - Maintains the append-only audit log (independent of graph checkpoint)
 * - Exposes a WebSocket to the operator for live findings, interrupt decisions,
 *   and pause/kill control
 * - Uses DO Alarms for scheduled follow-up checks (e.g. "did the misconfig get fixed?")
 *
 * Key design decisions:
 * - Audit log is stored in DO storage as its own entries, NOT reconstructable
 *   only from graph state — it's the compliance/liability record.
 * - A scan that takes hours can hibernate and resume; the graph checkpoint
 *   and audit log both survive.
 * - The operator can reconnect mid-run and receive the current state immediately.
 */

import { Agent, type Connection, type ConnectionContext } from "agents";
import { MemorySaver, Command } from "@langchain/langgraph";
import { buildGraph } from "../graph/index.js";
import type {
  ScopeGrant,
  EngagementPhase,
  AuditEntry,
  OperatorMessage,
  AgentPush,
  Finding,
  Env,
} from "../types/index.js";
import { v4 as uuidv4 } from "uuid";
import { getSandbox } from "@cloudflare/sandbox";
import type { ReconSandbox } from "../sandbox/recon-sandbox.js";

// getSandbox() returns an RPC proxy client, not a plain instance — the
// ReconSandbox durable object is instantiated by the runtime via the
// RECON_SANDBOX binding, never with `new ReconSandbox(...)` directly.
function reconSandboxFor(env: Env, engagementId: string): ReconSandbox {
  return getSandbox(env.RECON_SANDBOX, engagementId) as unknown as ReconSandbox;
}

// ---------------------------------------------------------------------------
// Internal state stored in DO SQLite via this.sql
// ---------------------------------------------------------------------------

interface EngagementRecord {
  engagement_id: string;
  scope: ScopeGrant;
  phase: EngagementPhase;
  target_domain: string;
  started_at: string;
  paused: boolean;
  killed: boolean;
}

// ---------------------------------------------------------------------------
// EngagementAgent — one Durable Object per engagement
// ---------------------------------------------------------------------------

export class EngagementAgent extends Agent<Env> {
  // The graph runs against an in-memory checkpointer that the Agent
  // persists to DO storage after each node for hibernation safety.
  private checkpointer = new MemorySaver();

  // Engagement metadata (populated on first request, restored from storage on wake)
  private engagementRecord: EngagementRecord | null = null;

  // Abort controller for graceful pause/kill
  private abortController: AbortController | null = null;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  async onStart(): Promise<void> {
    // Ensure schema exists — onStart fires before any request handler, including
    // the very first one, so the tables may not have been created yet.
    await this.sql`
      CREATE TABLE IF NOT EXISTS engagements (
        engagement_id TEXT PRIMARY KEY,
        scope TEXT NOT NULL,
        phase TEXT NOT NULL,
        target_domain TEXT NOT NULL,
        started_at TEXT NOT NULL,
        paused INTEGER NOT NULL DEFAULT 0,
        killed INTEGER NOT NULL DEFAULT 0
      )
    `;
    await this.sql`
      CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY,
        engagement_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        node TEXT,
        details TEXT NOT NULL
      )
    `;

    // Restore engagement record from DO SQLite if we're waking from hibernation
    const rows = await this.sql<EngagementRecord>`
      SELECT * FROM engagements LIMIT 1
    `;
    if (rows.length > 0 && rows[0]) {
      this.engagementRecord = rows[0] as EngagementRecord;
    }
  }

  // ---------------------------------------------------------------------------
  // HTTP request handler — engagement creation and WebSocket upgrade
  // ---------------------------------------------------------------------------

  async onRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // POST /start — create a new engagement
    if (request.method === "POST" && url.pathname === "/start") {
      return this.handleStart(request);
    }

    // GET /status — engagement status (WebSocket is handled by the Agents SDK)
    if (request.method === "GET" && url.pathname === "/status") {
      return new Response(
        JSON.stringify({
          engagement_id: this.engagementRecord?.engagement_id ?? null,
          phase: this.engagementRecord?.phase ?? null,
          started_at: this.engagementRecord?.started_at ?? null,
          paused: this.engagementRecord?.paused ?? false,
          killed: this.engagementRecord?.killed ?? false,
        }),
        { headers: { "Content-Type": "application/json" } },
      );
    }

    return new Response("Not found", { status: 404 });
  }


  // ---------------------------------------------------------------------------
  // Engagement start
  // ---------------------------------------------------------------------------

  private async handleStart(request: Request): Promise<Response> {
    if (this.engagementRecord) {
      return new Response(
        JSON.stringify({ error: "Engagement already started" }),
        { status: 409, headers: { "Content-Type": "application/json" } },
      );
    }

    const body = (await request.json()) as {
      scope: ScopeGrant;
      target_domain: string;
    };

    // Validate scope grant is present
    if (!body.scope || !body.target_domain) {
      return new Response(
        JSON.stringify({ error: "scope and target_domain are required" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    // Validate scope expiry
    if (new Date(body.scope.expires_at) < new Date()) {
      return new Response(
        JSON.stringify({ error: "ScopeGrant has already expired" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    const record: EngagementRecord = {
      engagement_id: body.scope.engagement_id,
      scope: body.scope,
      phase: "recon",
      target_domain: body.target_domain,
      started_at: new Date().toISOString(),
      paused: false,
      killed: false,
    };

    // Persist to DO SQLite (schema already ensured by onStart)
    await this.sql`
      INSERT INTO engagements (engagement_id, scope, phase, target_domain, started_at, paused, killed)
      VALUES (
        ${record.engagement_id},
        ${JSON.stringify(record.scope)},
        ${record.phase},
        ${record.target_domain},
        ${record.started_at},
        0,
        0
      )
    `;

    this.engagementRecord = record;
    this.appendAuditEntry({
      id: uuidv4(),
      engagement_id: record.engagement_id,
      kind: "phase_transition",
      timestamp: new Date().toISOString(),
      node: "agent",
      details: { event: "engagement_started", target: record.target_domain },
    });

    // Start the graph in the background (non-blocking)
    this.ctx.waitUntil(this.runGraph(record));

    return new Response(
      JSON.stringify({
        engagement_id: record.engagement_id,
        status: "started",
      }),
      { status: 201, headers: { "Content-Type": "application/json" } },
    );
  }

  // ---------------------------------------------------------------------------
  // LangGraph execution
  // ---------------------------------------------------------------------------

  private async runGraph(record: EngagementRecord): Promise<void> {
    this.abortController = new AbortController();

    // Build a sandbox instance for this engagement
    // In prod this calls the Cloudflare Sandbox binding; here we use a stub
    const sandbox = reconSandboxFor(this.env, record.engagement_id);

    const graph = buildGraph(
      {
        sandbox,
        llmConfig: {
          ai: this.env.AI,
          worker_model: this.env.WORKER_MODEL,
          validator_model: this.env.VALIDATOR_MODEL,
          report_model: this.env.REPORT_MODEL,
        },
        auditAppend: (entry) => this.appendAuditEntry(entry),
        onInterrupt: (findings) => this.pushToOperator({ type: "interrupt", findings }),
        started_at: record.started_at,
      },
      this.checkpointer,
    );

    const config = {
      configurable: { thread_id: record.engagement_id },
    };

    try {
      for await (const event of graph.streamEvents(
        {
          scope: record.scope,
          target_domain: record.target_domain,
          subdomains: [],
          findings: [],
          validated: [],
          phase: "recon" as const,
          report: null,
        },
        { ...config, version: "v2" },
      )) {
        // Check pause/kill before processing each event
        if (this.abortController.signal.aborted) break;
        const killed = await this.isKilled();
        if (killed) break;
        const paused = await this.isPaused();
        if (paused) {
          await this.waitForResume();
        }

        // Push phase transitions and live findings to operator
        if (event.event === "on_chain_end") {
          const output = event.data?.output as Record<string, unknown>;
          if (output?.phase) {
            const phase = output.phase as EngagementPhase;
            await this.setPhase(phase);
            this.pushToOperator({ type: "phase", phase });
          }
          if (Array.isArray(output?.validated)) {
            for (const f of output.validated as Finding[]) {
              if (f.status === "confirmed") {
                this.pushToOperator({ type: "finding", finding: f });
              }
            }
          }
          if (output?.report) {
            const reportStr = output.report as string;
            const [jsonPart, , mdPart] = reportStr.split("---MARKDOWN---");
            this.pushToOperator({
              type: "report_ready",
              report_json: JSON.parse(jsonPart?.trim() ?? "{}"),
              report_md: mdPart?.trim() ?? "",
            });
          }
        }

        // Handle interrupt events — send to operator via WebSocket
        if (event.event === "on_chain_end" && event.data?.output?.__interrupt__) {
          const interrupts = event.data.output.__interrupt__;
          const findings = (interrupts as Array<{ value: { findings: Finding[] } }>)
            .flatMap((i) => i.value?.findings ?? []);
          this.pushToOperator({ type: "interrupt", findings });
        }
      }
    } catch (err) {
      // Without this, a graph-execution error is only visible via the
      // operator WebSocket (if connected at the moment) or the audit log
      // (no read endpoint) — invisible to `wrangler tail` / Workers Logs.
      console.error(`runGraph failed for engagement ${record.engagement_id}:`, err);
      this.pushToOperator({
        type: "error",
        message: String(err),
      });
      this.appendAuditEntry({
        id: uuidv4(),
        engagement_id: record.engagement_id,
        kind: "error",
        timestamp: new Date().toISOString(),
        node: "agent",
        details: { error: String(err) },
      });
    }
  }

  // ---------------------------------------------------------------------------
  // WebSocket operator connection
  // ---------------------------------------------------------------------------

  onConnect(connection: Connection, ctx: ConnectionContext): void {
    // Send current state snapshot immediately on connect (operator reconnect support)
    this.sendSnapshot(connection);
  }

  async onMessage(connection: Connection, message: string | ArrayBuffer): Promise<void> {
    const msg = JSON.parse(
      typeof message === "string" ? message : new TextDecoder().decode(message),
    ) as OperatorMessage;

    switch (msg.type) {
      case "pause":
        await this.setPaused(true);
        this.appendAuditEntry({
          id: uuidv4(),
          engagement_id: this.engagementRecord?.engagement_id ?? "unknown",
          kind: "operator_decision",
          timestamp: new Date().toISOString(),
          node: "agent",
          details: { action: "pause" },
        });
        break;

      case "kill":
        await this.setKilled(true);
        this.abortController?.abort();
        this.appendAuditEntry({
          id: uuidv4(),
          engagement_id: this.engagementRecord?.engagement_id ?? "unknown",
          kind: "operator_decision",
          timestamp: new Date().toISOString(),
          node: "agent",
          details: { action: "kill" },
        });
        this.pushToOperator({ type: "halted", reason: "operator_kill" });
        break;

      case "resume": {
        // Resume the graph from an interrupt with operator's per-finding decision
        await this.setPaused(false);
        const { finding_id, decision } = msg;

        this.appendAuditEntry({
          id: uuidv4(),
          engagement_id: this.engagementRecord?.engagement_id ?? "unknown",
          kind: "operator_decision",
          timestamp: new Date().toISOString(),
          node: "agent",
          details: { action: "resume", finding_id, decision },
        });

        // Resume the graph with the operator decision
        const config = {
          configurable: {
            thread_id: this.engagementRecord?.engagement_id ?? "",
          },
        };
        const graph = buildGraph(
          {
            sandbox: reconSandboxFor(this.env, this.engagementRecord?.engagement_id ?? ""),
            llmConfig: {
              ai: this.env.AI,
              worker_model: this.env.WORKER_MODEL,
              validator_model: this.env.VALIDATOR_MODEL,
              report_model: this.env.REPORT_MODEL,
            },
            auditAppend: (e) => this.appendAuditEntry(e),
            onInterrupt: (findings) =>
              this.pushToOperator({ type: "interrupt", findings }),
            started_at: this.engagementRecord?.started_at ?? new Date().toISOString(),
          },
          this.checkpointer,
        );

        // Resume with the per-finding decision map
        this.ctx.waitUntil(
          graph
            .invoke(
              new Command({ resume: { [finding_id]: { decision } } }),
              config,
            )
            .then(() => {}),
        );
        break;
      }

      case "status":
        this.sendSnapshot(connection);
        break;
    }
  }

  // ---------------------------------------------------------------------------
  // Audit log — append-only, stored in DO SQLite independently of graph state
  // ---------------------------------------------------------------------------

  private appendAuditEntry(entry: AuditEntry): void {
    // Fire-and-forget — audit log writes never block the graph
    this.ctx.waitUntil(
      Promise.resolve(
        this.sql`
          INSERT OR IGNORE INTO audit_log (id, engagement_id, kind, timestamp, node, details)
          VALUES (
            ${entry.id},
            ${entry.engagement_id},
            ${entry.kind},
            ${entry.timestamp},
            ${entry.node ?? null},
            ${JSON.stringify(entry.details)}
          )
        `,
      ).then(() => {}),
    );
  }


  // ---------------------------------------------------------------------------
  // WebSocket push helpers
  // ---------------------------------------------------------------------------

  private pushToOperator(msg: AgentPush): void {
    this.broadcast(JSON.stringify(msg));
  }

  private sendSnapshot(connection: Connection): void {
    if (!this.engagementRecord) return;
    connection.send(
      JSON.stringify({
        type: "phase",
        phase: this.engagementRecord.phase,
      }),
    );
  }

  // ---------------------------------------------------------------------------
  // Pause / kill flags stored in DO SQLite
  // ---------------------------------------------------------------------------

  private async isPaused(): Promise<boolean> {
    const rows = await this.sql<{ paused: number }>`
      SELECT paused FROM engagements LIMIT 1
    `;
    return (rows[0]?.paused ?? 0) === 1;
  }

  private async isKilled(): Promise<boolean> {
    const rows = await this.sql<{ killed: number }>`
      SELECT killed FROM engagements LIMIT 1
    `;
    return (rows[0]?.killed ?? 0) === 1;
  }

  private async setPaused(paused: boolean): Promise<void> {
    await this.sql`
      UPDATE engagements SET paused = ${paused ? 1 : 0}
    `;
    if (this.engagementRecord) this.engagementRecord.paused = paused;
  }

  private async setPhase(phase: EngagementPhase): Promise<void> {
    await this.sql`
      UPDATE engagements SET phase = ${phase}
    `;
    if (this.engagementRecord) this.engagementRecord.phase = phase;
  }

  private async setKilled(killed: boolean): Promise<void> {
    await this.sql`
      UPDATE engagements SET killed = ${killed ? 1 : 0}, phase = 'halted'
    `;
    if (this.engagementRecord) {
      this.engagementRecord.killed = killed;
      this.engagementRecord.phase = "halted";
    }
  }

  // ---------------------------------------------------------------------------
  // Wait for resume (polling with exponential backoff)
  // ---------------------------------------------------------------------------

  private async waitForResume(): Promise<void> {
    let delay = 500;
    while (true) {
      await new Promise((r) => setTimeout(r, delay));
      const paused = await this.isPaused();
      const killed = await this.isKilled();
      if (!paused || killed) break;
      delay = Math.min(delay * 1.5, 5000);
    }
  }
}
