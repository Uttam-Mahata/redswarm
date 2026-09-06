/**
 * src/types/index.ts
 *
 * Shared types for redswarm — imported by every node, tool wrapper, and the Agent.
 * These are the canonical definitions from docs/langgraph-flow.md and docs/scope-and-safety.md.
 */

// ---------------------------------------------------------------------------
// ScopeGrant — authorization model (see docs/scope-and-safety.md)
// ---------------------------------------------------------------------------

export interface ScopeGrant {
  /** Unique identifier for this engagement */
  engagement_id: string;
  /** Who approved this engagement */
  authorized_by: string;
  /** Exact domains/subdomains in scope */
  domains: string[];
  /** CIDR ranges in scope, if any */
  ip_ranges: string[];
  /** Explicit carve-outs within an in-scope range */
  excluded: string[];
  /**
   * Findings at or above this severity always need human sign-off.
   * One of: "low" | "medium" | "high" | "critical"
   */
  max_severity_auto_report: Severity;
  /** false = passive recon only; must be explicitly opted in to allow active probing */
  allow_active_probing: boolean;
  /** ISO 8601 string — engagements are time-boxed */
  expires_at: string;
}

// ---------------------------------------------------------------------------
// Finding — individual vulnerability candidate
// ---------------------------------------------------------------------------

export type Severity = "low" | "medium" | "high" | "critical";
export type FindingStatus =
  | "unverified"
  | "confirmed"
  | "false_positive"
  | "needs_human_review";

export interface Finding {
  id: string;
  subdomain: string;
  /** e.g. "misconfigured_header", "ssrf", "xss" */
  category: string;
  /** Raw tool output, request/response snippets */
  evidence: Record<string, unknown>;
  severity: Severity;
  status: FindingStatus;
  /** CVE references enriched during validation */
  cve_refs?: string[];
  /** Plain-language summary written by the validator */
  description?: string;
  /** Suggested remediation */
  remediation?: string;
  /** Populated after human approval */
  approved_by?: string;
  approved_at?: string;
  /** Which validator node produced this */
  confirmed_by?: string;
}

// ---------------------------------------------------------------------------
// EngagementState — LangGraph state schema
// ---------------------------------------------------------------------------

export type EngagementPhase =
  | "recon"
  | "aggregate"
  | "validate"
  | "report"
  | "halted";

export interface EngagementState {
  scope: ScopeGrant;
  target_domain: string;
  subdomains: string[];
  findings: Finding[];
  validated: Finding[];
  phase: EngagementPhase;
  report: string | null;
}

// ---------------------------------------------------------------------------
// Audit log entry
// ---------------------------------------------------------------------------

export type AuditEventKind =
  | "tool_call"
  | "llm_call"
  | "scope_check_pass"
  | "scope_check_reject"
  | "operator_decision"
  | "phase_transition"
  | "error";

export interface AuditEntry {
  id: string;
  engagement_id: string;
  kind: AuditEventKind;
  timestamp: string;
  node?: string;
  details: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// WebSocket operator messages
// ---------------------------------------------------------------------------

export type OperatorMessage =
  | { type: "pause" }
  | { type: "kill" }
  | { type: "resume"; finding_id: string; decision: "approve" | "reject" | "deeper" }
  | { type: "status" };

export type AgentPush =
  | { type: "finding"; finding: Finding }
  | { type: "phase"; phase: EngagementPhase }
  | { type: "interrupt"; findings: Finding[] }
  | { type: "report_ready"; report_json: unknown; report_md: string }
  | { type: "halted"; reason: string }
  | { type: "error"; message: string };

// ---------------------------------------------------------------------------
// Worker env bindings (wrangler.jsonc bindings injected at runtime)
// ---------------------------------------------------------------------------

export type Env = Cloudflare.Env;
