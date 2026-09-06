/**
 * src/graph/nodes/orchestrator.ts
 *
 * Orchestrator node — entry point of the LangGraph graph.
 *
 * Responsibilities:
 * 1. Run subdomain enumeration as its first tool call (via Sandbox)
 * 2. Filter discovered subdomains against ScopeGrant
 * 3. Batch subdomains (10–20 per batch) and Send() a Worker task per batch
 *
 * Uses Send() so Worker nodes run in parallel — the number of batches is only
 * known at runtime (this is the standard LangGraph map-reduce fan-out pattern).
 */

import { Send } from "@langchain/langgraph";
import { EngagementState } from "../state.js";
import { scopeCheck } from "../../tools/scope-check.js";
import type { ReconSandbox } from "../../sandbox/recon-sandbox.js";
import type { AuditEntry } from "../../types/index.js";

// ---------------------------------------------------------------------------
// Worker task input (what each Send() carries)
// ---------------------------------------------------------------------------

export interface WorkerTaskInput {
  scope: EngagementState["scope"];
  subdomains: string[];
  /** Batch index for logging */
  batch_index: number;
}

// ---------------------------------------------------------------------------
// Orchestrator node
// ---------------------------------------------------------------------------

const BATCH_SIZE = 15;

/**
 * The orchestrator is called from a conditional edge off START so it can
 * return Send() objects for the fan-out.
 *
 * Returns: Array<Send("worker", WorkerTaskInput)>
 */
export async function orchestratorNode(
  state: EngagementState,
  context: { sandbox: ReconSandbox; auditAppend: (e: AuditEntry) => void },
): Promise<Send[]> {
  const { scope, target_domain } = state;

  // --- 1. Scope-check the target domain itself --------------------------------
  const checkResult = scopeCheck(target_domain, scope, "orchestrator");
  context.auditAppend(checkResult.audit);

  // --- 2. Subdomain enumeration in Sandbox ------------------------------------
  const enumResult = await context.sandbox.subdomainEnum(target_domain, scope);

  context.auditAppend({
    id: crypto.randomUUID(),
    engagement_id: scope.engagement_id,
    kind: "tool_call",
    timestamp: new Date().toISOString(),
    node: "orchestrator",
    details: {
      tool: "subdomainEnum",
      target: target_domain,
      exit_code: enumResult.exit_code,
      duration_ms: enumResult.duration_ms,
    },
  });

  // --- 3. Extract and scope-filter discovered subdomains ----------------------
  const discovered: string[] =
    (enumResult.parsed?.subdomains as string[] | undefined) ?? [];

  const inScopeSubdomains: string[] = [];
  for (const sub of discovered) {
    try {
      const check = scopeCheck(sub, scope, "orchestrator");
      context.auditAppend(check.audit);
      inScopeSubdomains.push(sub);
    } catch {
      // Out of scope — silently drop (audit entry already appended inside scopeCheck)
      context.auditAppend({
        id: crypto.randomUUID(),
        engagement_id: scope.engagement_id,
        kind: "scope_check_reject",
        timestamp: new Date().toISOString(),
        node: "orchestrator",
        details: { subdomain: sub, reason: "out_of_scope_discovered" },
      });
    }
  }

  // Always include the root target domain
  if (!inScopeSubdomains.includes(target_domain)) {
    inScopeSubdomains.unshift(target_domain);
  }

  // --- 4. Batch and fan out via Send() ----------------------------------------
  const batches = chunkArray(inScopeSubdomains, BATCH_SIZE);

  return batches.map(
    (batch, index) =>
      new Send("worker", {
        scope,
        subdomains: batch,
        batch_index: index,
      } satisfies WorkerTaskInput),
  );
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function chunkArray<T>(arr: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}
