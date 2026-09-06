/**
 * src/graph/state.ts
 *
 * LangGraph state schema for redswarm — matches docs/langgraph-flow.md exactly.
 *
 * Uses Annotated reducers so parallel Worker and Validator Send() nodes accumulate
 * findings into the list rather than overwriting each other's results.
 */

import { Annotation } from "@langchain/langgraph";
import type {
  ScopeGrant,
  Finding,
  EngagementPhase,
} from "../types/index.js";

// ---------------------------------------------------------------------------
// EngagementState — graph-level state
// ---------------------------------------------------------------------------

export const EngagementStateAnnotation = Annotation.Root({
  /** Authorization grant — set once at engagement start, never mutated */
  scope: Annotation<ScopeGrant>(),

  /** The root target domain for this engagement */
  target_domain: Annotation<string>(),

  /**
   * Subdomains discovered by the Orchestrator — accumulated via array concat
   * with deduplication.
   */
  subdomains: Annotation<string[]>({
    reducer: (current, update) => {
      const set = new Set([...current, ...update]);
      return Array.from(set);
    },
    default: () => [],
  }),

  /**
   * Candidate findings from Worker nodes — accumulated (not overwritten)
   * so parallel Workers can each append their findings.
   */
  findings: Annotation<Finding[]>({
    reducer: (current, update) => [...current, ...update],
    default: () => [],
  }),

  /**
   * Validated findings from ExploitValidation nodes — accumulated so
   * parallel Validator Send() nodes each contribute.
   */
  validated: Annotation<Finding[]>({
    reducer: (current, update) => [...current, ...update],
    default: () => [],
  }),

  /**
   * Current phase — simple last-write-wins.
   */
  phase: Annotation<EngagementPhase>({
    reducer: (_current, update) => update,
    default: () => "recon" as EngagementPhase,
  }),

  /** Final compiled report — null until the Report node runs */
  report: Annotation<string | null>({
    reducer: (_current, update) => update,
    default: () => null,
  }),
});

export type EngagementState = typeof EngagementStateAnnotation.State;
