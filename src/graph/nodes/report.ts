/**
 * src/graph/nodes/report.ts
 *
 * Report node — compiles confirmed + approved findings into the final report.
 *
 * Two outputs (per docs/report-format.md):
 * 1. Machine-readable JSON artifact
 * 2. Human-readable Markdown summary
 *
 * Evidence redaction: any evidence containing likely credentials, PII, or
 * session tokens is masked before the report is distributed.
 * Full unredacted evidence remains only in the Agent's audit log.
 */

import { callLLM, type LLMConfig } from "../../tools/ai-gateway.js";
import type { EngagementState } from "../state.js";
import type { Finding, AuditEntry } from "../../types/index.js";
import { v4 as uuidv4 } from "uuid";

// ---------------------------------------------------------------------------
// Report node context
// ---------------------------------------------------------------------------

export interface ReportNodeContext {
  llmConfig: LLMConfig;
  auditAppend: (e: AuditEntry) => void;
  started_at: string;
}

// ---------------------------------------------------------------------------
// Report node entry point
// ---------------------------------------------------------------------------

export async function reportNode(
  state: EngagementState,
  context: ReportNodeContext,
): Promise<Partial<EngagementState>> {
  const { scope, validated, target_domain } = state;

  // Only include confirmed findings (operator-approved)
  const confirmed = validated.filter((f) => f.status === "confirmed");
  const falsePosCount = validated.filter(
    (f) => f.status === "false_positive",
  ).length;

  // Redact evidence in the distributed report
  const redactedFindings = confirmed.map(redactFinding);

  // Build JSON artifact
  const jsonReport = buildJsonReport(
    scope,
    target_domain,
    redactedFindings,
    falsePosCount,
    context.started_at,
  );

  // Build Markdown summary using strong LLM model
  const markdownReport = await buildMarkdownReport(
    jsonReport,
    state,
    context,
  );

  context.auditAppend({
    id: uuidv4(),
    engagement_id: scope.engagement_id,
    kind: "phase_transition",
    timestamp: new Date().toISOString(),
    node: "report",
    details: {
      confirmed_count: confirmed.length,
      false_positive_count: falsePosCount,
    },
  });

  // Return both as a combined string (JSON + separator + Markdown)
  const fullReport = JSON.stringify(jsonReport, null, 2) +
    "\n\n---MARKDOWN---\n\n" +
    markdownReport;

  return { report: fullReport, phase: "report" };
}

// ---------------------------------------------------------------------------
// JSON report builder
// ---------------------------------------------------------------------------

function buildJsonReport(
  scope: EngagementState["scope"],
  target_domain: string,
  findings: Finding[],
  falsePosCount: number,
  started_at: string,
) {
  return {
    engagement_id: scope.engagement_id,
    target_domain,
    scope: {
      authorized_by: scope.authorized_by,
      domains: scope.domains,
      ip_ranges: scope.ip_ranges,
      excluded: scope.excluded,
      allow_active_probing: scope.allow_active_probing,
      expires_at: scope.expires_at,
    },
    started_at,
    completed_at: new Date().toISOString(),
    findings: findings.map((f) => ({
      id: f.id,
      subdomain: f.subdomain,
      category: f.category,
      severity: f.severity,
      description: f.description ?? "",
      evidence: f.evidence,
      cve_refs: f.cve_refs ?? [],
      confirmed_by: f.confirmed_by ?? "exploit_validation",
      approved_by: f.approved_by ?? "auto",
      approved_at: f.approved_at ?? new Date().toISOString(),
      remediation: f.remediation ?? "",
    })),
    excluded_summary: {
      false_positive_count: falsePosCount,
      out_of_scope_dropped_count: 0, // tracked in audit log
    },
    audit_log_ref: `engagement:${scope.engagement_id}:audit_log`,
  };
}

// ---------------------------------------------------------------------------
// Markdown report builder (strong LLM)
// ---------------------------------------------------------------------------

async function buildMarkdownReport(
  jsonReport: ReturnType<typeof buildJsonReport>,
  state: EngagementState,
  context: ReportNodeContext,
): Promise<string> {
  const findingsSummary = jsonReport.findings
    .map(
      (f) =>
        `- [${f.severity.toUpperCase()}] ${f.category} on ${f.subdomain}: ${f.description}`,
    )
    .join("\n");

  const systemPrompt = `You are a professional penetration testing report writer.
Write a clear, structured security assessment report in Markdown.

The report must include these sections in order:
1. ## Executive Summary — scope, duration, finding counts by severity, one-paragraph overall risk statement
2. ## Methodology — recon and validation steps run; explicitly state the non-destructive validation policy
3. ## Findings — ordered by severity (critical first), each with: description, affected asset, evidence summary, remediation, CVE refs
4. ## Out-of-Scope / Excluded Notes — items discovered but dropped; reassure client scope was respected
5. ## Appendix: Audit Trail Excerpt — brief excerpt showing how key findings were reached

Use professional, clear language. Do not speculate beyond the evidence.`;

  const result = await callLLM({
    tier: "report",
    config: context.llmConfig,
    engagement_id: state.scope.engagement_id,
    node: "report",
    max_tokens: 4096,
    messages: [
      { role: "system", content: systemPrompt },
      {
        role: "user",
        content: `Generate the security assessment report for this engagement:\n\n${JSON.stringify(jsonReport, null, 2)}`,
      },
    ],
  });

  context.auditAppend({
    id: uuidv4(),
    engagement_id: state.scope.engagement_id,
    kind: "llm_call",
    timestamp: new Date().toISOString(),
    node: "report",
    details: { tier: "report", action: "markdown_synthesis" },
  });

  return result.content;
}

// ---------------------------------------------------------------------------
// Evidence redaction
// ---------------------------------------------------------------------------

const REDACTION_PATTERNS = [
  // Credentials / tokens
  /(?:password|passwd|pwd|secret|token|api_key|apikey|access_key|auth)[^\w]?[:=]\s*["']?([^\s"',;>]{4,})/gi,
  // Session tokens (long base64-like strings)
  /\b[A-Za-z0-9+/]{32,}={0,2}\b/g,
  // Email addresses
  /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
];

const REDACTED_MARKER = "[REDACTED]";

function redactString(s: string): string {
  let result = s;
  for (const pattern of REDACTION_PATTERNS) {
    result = result.replace(pattern, REDACTED_MARKER);
  }
  return result;
}

function redactValue(v: unknown): unknown {
  if (typeof v === "string") return redactString(v);
  if (typeof v === "object" && v !== null) {
    return Object.fromEntries(
      Object.entries(v as Record<string, unknown>).map(([k, val]) => [
        k,
        redactValue(val),
      ]),
    );
  }
  return v;
}

function redactFinding(finding: Finding): Finding {
  return {
    ...finding,
    evidence: redactValue(finding.evidence) as Record<string, unknown>,
  };
}
