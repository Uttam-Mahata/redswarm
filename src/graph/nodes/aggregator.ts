/**
 * src/graph/nodes/aggregator.ts
 *
 * Aggregator node — pure function, no LLM call.
 *
 * Dedupes and merges all Worker findings by (subdomain, category, evidence_signature),
 * then fans out to ExploitValidation nodes — one Send() per unique finding.
 *
 * This is a pure map function: state.findings in → deduplicated findings out,
 * each dispatched via Send("exploit_validation", FindingTaskInput).
 */

import { Send } from "@langchain/langgraph";
import type { EngagementState } from "../state.js";
import type { Finding } from "../../types/index.js";

// ---------------------------------------------------------------------------
// Validator task input
// ---------------------------------------------------------------------------

export interface FindingTaskInput {
  finding: Finding;
  scope: EngagementState["scope"];
}

// ---------------------------------------------------------------------------
// Aggregator node — returns Send[] for the fan-out
// ---------------------------------------------------------------------------

/**
 * Called from a conditional edge after all Worker nodes have completed.
 * Returns an array of Send("exploit_validation", ...) — one per unique finding.
 */
export function aggregatorNode(state: EngagementState): Send[] {
  const deduped = deduplicateFindings(state.findings);

  return deduped.map(
    (finding) =>
      new Send("exploit_validation", {
        finding,
        scope: state.scope,
      } satisfies FindingTaskInput),
  );
}

// ---------------------------------------------------------------------------
// Deduplication logic
// ---------------------------------------------------------------------------

/**
 * Deduplicates findings by (subdomain, category, evidence_signature).
 * When duplicates exist, merges evidence from all copies.
 */
function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();

  for (const finding of findings) {
    const key = dedupeKey(finding);
    if (seen.has(key)) {
      // Merge evidence from duplicate
      const existing = seen.get(key)!;
      existing.evidence = { ...existing.evidence, ...finding.evidence };
      // Take the higher severity
      if (severityRank(finding.severity) > severityRank(existing.severity)) {
        existing.severity = finding.severity;
      }
    } else {
      seen.set(key, { ...finding });
    }
  }

  return Array.from(seen.values());
}

function dedupeKey(finding: Finding): string {
  const evidenceSig = stableHash(finding.evidence);
  return `${finding.subdomain}::${finding.category}::${evidenceSig}`;
}

const SEVERITY_RANK: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function severityRank(s: string): number {
  return SEVERITY_RANK[s] ?? 0;
}

/** Stable JSON hash — order-independent */
function stableHash(obj: Record<string, unknown>): string {
  const sorted = Object.keys(obj)
    .sort()
    .map((k) => `${k}:${JSON.stringify(obj[k])}`)
    .join("|");
  let h = 0;
  for (let i = 0; i < sorted.length; i++) {
    h = ((h << 5) - h + sorted.charCodeAt(i)) | 0;
  }
  return Math.abs(h).toString(36);
}
