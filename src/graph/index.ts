/**
 * src/graph/index.ts
 *
 * LangGraph graph wiring — assembles all nodes into the full engagement graph.
 *
 * Graph topology (from docs/langgraph-flow.md):
 *
 *   START
 *    │ conditional_edge → orchestratorFanOut → Send[] to "worker"
 *    ▼
 *   worker (parallel N)
 *    │ edge → aggregator
 *    ▼
 *   aggregator
 *    │ conditional_edge → aggregatorFanOut → Send[] to "exploit_validation"
 *    ▼
 *   exploit_validation (parallel N)
 *    │ edge → human_interrupt_gate
 *    ▼
 *   human_interrupt_gate → report → END
 */

import {
  StateGraph,
  START,
  END,
  interrupt,
  Command,
} from "@langchain/langgraph";
import { EngagementStateAnnotation, type EngagementState } from "./state.js";
import { orchestratorNode } from "./nodes/orchestrator.js";
import { workerNode, type WorkerNodeContext } from "./nodes/worker.js";
import { aggregatorNode } from "./nodes/aggregator.js";
import {
  exploitValidationNode,
  type ValidatorNodeContext,
} from "./nodes/exploit-validation.js";
import { reportNode, type ReportNodeContext } from "./nodes/report.js";
import type { Finding, AuditEntry } from "../types/index.js";
import type { ReconSandbox } from "../sandbox/recon-sandbox.js";
import type { LLMConfig } from "../tools/ai-gateway.js";

// ---------------------------------------------------------------------------
// Runtime context passed into graph nodes
// ---------------------------------------------------------------------------

export interface GraphRunContext {
  sandbox: ReconSandbox;
  llmConfig: LLMConfig;
  auditAppend: (e: AuditEntry) => void;
  onInterrupt: (findings: Finding[]) => void;
  started_at: string;
}

// ---------------------------------------------------------------------------
// Graph builder
// The StateGraph type accumulates known node names via generics as you chain
// addNode() calls. We use 'as any' on the final compile step to avoid the
// complex generic inference chain, keeping the runtime behavior correct.
// ---------------------------------------------------------------------------

export function buildGraph(ctx: GraphRunContext, checkpointer: unknown) {
  // Build the graph by chaining .addNode() calls so TypeScript can track
  // accumulated node names for edge type checking.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const graph = new StateGraph(EngagementStateAnnotation) as any;

  // --- Nodes ---

  graph.addNode("orchestrator", async (_state: EngagementState) => {
    return {}; // orchestrator drives fan-out via conditional edge below
  });

  graph.addNode("worker", async (input: unknown) => {
    const workerCtx: WorkerNodeContext = {
      sandbox: ctx.sandbox,
      llmConfig: ctx.llmConfig,
      auditAppend: ctx.auditAppend,
    };
    return workerNode(input as Parameters<typeof workerNode>[0], workerCtx);
  });

  graph.addNode("aggregator", async (_state: EngagementState) => {
    return {}; // fan-out driven by conditional edge
  });

  graph.addNode("exploit_validation", async (input: unknown) => {
    const validatorCtx: ValidatorNodeContext = {
      sandbox: ctx.sandbox,
      llmConfig: ctx.llmConfig,
      auditAppend: ctx.auditAppend,
    };
    return exploitValidationNode(
      input as Parameters<typeof exploitValidationNode>[0],
      validatorCtx,
    );
  });

  graph.addNode(
    "human_interrupt_gate",
    async (state: EngagementState): Promise<Partial<EngagementState>> => {
      return humanInterruptGateNode(state);
    },
  );

  graph.addNode("report", async (state: EngagementState) => {
    const reportCtx: ReportNodeContext = {
      llmConfig: ctx.llmConfig,
      auditAppend: ctx.auditAppend,
      started_at: ctx.started_at,
    };
    return reportNode(state, reportCtx);
  });

  // --- Edges ---

  // START → orchestrator fan-out via conditional edge → worker Send[]
  graph.addConditionalEdges(
    START,
    async (state: EngagementState) => {
      return orchestratorNode(state, {
        sandbox: ctx.sandbox,
        auditAppend: ctx.auditAppend,
      });
    },
    ["worker"],
  );

  // worker → aggregator (waits for all parallel workers)
  graph.addEdge("worker", "aggregator");

  // aggregator → exploit_validation fan-out
  graph.addConditionalEdges("aggregator", aggregatorNode, [
    "exploit_validation",
  ]);

  // exploit_validation → human_interrupt_gate
  graph.addEdge("exploit_validation", "human_interrupt_gate");

  // human_interrupt_gate → report
  graph.addEdge("human_interrupt_gate", "report");

  // report → END
  graph.addEdge("report", END);

  return graph.compile({ checkpointer });
}

// ---------------------------------------------------------------------------
// Human interrupt gate node
// ---------------------------------------------------------------------------

async function humanInterruptGateNode(
  state: EngagementState,
): Promise<Partial<EngagementState>> {
  const { validated, scope } = state;

  const needsReview = validated.filter(
    (f) =>
      f.status === "needs_human_review" ||
      (f.status === "confirmed" &&
        severityAboveThreshold(f.severity, scope.max_severity_auto_report)),
  );

  if (needsReview.length === 0) {
    return {}; // pass through to report
  }

  // Pause for operator review
  const operatorDecisions = interrupt({
    type: "findings_need_review",
    findings: needsReview,
    message: `${needsReview.length} finding(s) require operator review.`,
  }) as Record<string, { decision: "approve" | "reject" | "deeper" }>;

  // Apply operator decisions
  const updatedValidated = state.validated.map((f) => {
    const decision = operatorDecisions[f.id];
    if (!decision) return f;

    switch (decision.decision) {
      case "approve":
        return {
          ...f,
          status: "confirmed" as const,
          approved_by: "operator",
          approved_at: new Date().toISOString(),
        };
      case "reject":
        return { ...f, status: "false_positive" as const };
      case "deeper":
        return {
          ...f,
          status: "needs_human_review" as const,
          evidence: {
            ...f.evidence,
            operator_note: "Manual deeper investigation requested",
          },
        };
      default:
        return f;
    }
  });

  return { validated: updatedValidated };
}

// ---------------------------------------------------------------------------
// Severity comparison
// ---------------------------------------------------------------------------

const SEVERITY_ORDER = ["low", "medium", "high", "critical"] as const;

function severityAboveThreshold(severity: string, threshold: string): boolean {
  const sIdx = SEVERITY_ORDER.indexOf(
    severity as (typeof SEVERITY_ORDER)[number],
  );
  const tIdx = SEVERITY_ORDER.indexOf(
    threshold as (typeof SEVERITY_ORDER)[number],
  );
  if (sIdx === -1 || tIdx === -1) return false;
  return sIdx >= tIdx;
}
