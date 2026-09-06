/**
 * src/graph/nodes/worker.ts
 *
 * Worker node — recon execution for a batch of subdomains.
 *
 * Given a batch of in-scope subdomains:
 * 1. Run port scan + HTTP header probe in Sandbox (one container per subdomain)
 * 2. Classify raw tool output → candidate Findings via cheap model (AI Gateway fast tier)
 * 3. Returns { findings: Finding[] } — accumulated by the reducer in state
 *
 * Does NOT attempt exploitation — recon only.
 */

import { v4 as uuidv4 } from "uuid";
import { EngagementState } from "../state.js";
import { scopeCheck } from "../../tools/scope-check.js";
import { callLLMJson, type LLMConfig } from "../../tools/ai-gateway.js";
import type { ReconSandbox } from "../../sandbox/recon-sandbox.js";
import type { Finding, AuditEntry, ScopeGrant } from "../../types/index.js";
import type { WorkerTaskInput } from "./orchestrator.js";

// ---------------------------------------------------------------------------
// Worker node — receives WorkerTaskInput from Send()
// ---------------------------------------------------------------------------

export interface WorkerNodeContext {
  sandbox: ReconSandbox;
  llmConfig: LLMConfig;
  auditAppend: (e: AuditEntry) => void;
}

/** Classification shape returned by the cheap LLM call */
interface ClassificationResult {
  findings: Array<{
    category: string;
    severity: "low" | "medium" | "high" | "critical";
    description: string;
    evidence_keys: string[];
  }>;
}

/**
 * Worker node entry point.
 * State update: appends newly discovered candidate findings to state.findings.
 */
export async function workerNode(
  input: WorkerTaskInput,
  context: WorkerNodeContext,
): Promise<Partial<EngagementState>> {
  const { scope, subdomains } = input;
  const newFindings: Finding[] = [];

  for (const subdomain of subdomains) {
    // Scope-check every subdomain before scanning
    try {
      const check = scopeCheck(subdomain, scope, "worker");
      context.auditAppend(check.audit);
    } catch (err) {
      context.auditAppend({
        id: uuidv4(),
        engagement_id: scope.engagement_id,
        kind: "scope_check_reject",
        timestamp: new Date().toISOString(),
        node: "worker",
        details: { subdomain, error: String(err) },
      });
      continue; // skip out-of-scope
    }

    const evidence = await gatherReconEvidence(subdomain, scope, context);
    const findings = await classifyEvidence(subdomain, evidence, scope, context);
    newFindings.push(...findings);
  }

  return { findings: newFindings };
}

// ---------------------------------------------------------------------------
// Recon evidence gathering
// ---------------------------------------------------------------------------

async function gatherReconEvidence(
  subdomain: string,
  scope: ScopeGrant,
  context: WorkerNodeContext,
): Promise<Record<string, unknown>> {
  const evidence: Record<string, unknown> = {};

  // Port scan
  try {
    const portResult = await context.sandbox.portScan(subdomain, scope);
    context.auditAppend({
      id: uuidv4(),
      engagement_id: scope.engagement_id,
      kind: "tool_call",
      timestamp: new Date().toISOString(),
      node: "worker",
      details: {
        tool: "portScan",
        target: subdomain,
        exit_code: portResult.exit_code,
        duration_ms: portResult.duration_ms,
      },
    });
    evidence.port_scan = portResult.parsed ?? {};
  } catch (err) {
    evidence.port_scan_error = String(err);
  }

  // HTTP header probe
  for (const scheme of ["https", "http"]) {
    try {
      const headerResult = await context.sandbox.httpHeaderProbe(
        `${scheme}://${subdomain}`,
        scope,
      );
      context.auditAppend({
        id: uuidv4(),
        engagement_id: scope.engagement_id,
        kind: "tool_call",
        timestamp: new Date().toISOString(),
        node: "worker",
        details: {
          tool: "httpHeaderProbe",
          target: `${scheme}://${subdomain}`,
          exit_code: headerResult.exit_code,
          duration_ms: headerResult.duration_ms,
        },
      });
      evidence[`headers_${scheme}`] = headerResult.parsed ?? {};
      if (headerResult.exit_code === 0) break; // HTTPS succeeded, skip HTTP
    } catch (err) {
      evidence[`headers_${scheme}_error`] = String(err);
    }
  }

  return evidence;
}

// ---------------------------------------------------------------------------
// LLM classification (fast tier)
// ---------------------------------------------------------------------------

async function classifyEvidence(
  subdomain: string,
  evidence: Record<string, unknown>,
  scope: ScopeGrant,
  context: WorkerNodeContext,
): Promise<Finding[]> {
  const evidenceJson = JSON.stringify(evidence, null, 2);

  // Cache key based on evidence signature — identical misconfig patterns across
  // many subdomains will hit the AI Gateway cache.
  const cacheKey = `worker_classify_${hashStr(evidenceJson)}`;

  let classification: ClassificationResult;
  try {
    classification = await callLLMJson<ClassificationResult>({
      tier: "worker",
      config: context.llmConfig,
      engagement_id: scope.engagement_id,
      node: "worker",
      cacheKey,
      messages: [
        {
          role: "system",
          content: WORKER_CLASSIFY_PROMPT,
        },
        {
          role: "user",
          content: `Subdomain: ${subdomain}\n\nEvidence:\n${evidenceJson}`,
        },
      ],
      max_tokens: 1024,
    });

    context.auditAppend({
      id: uuidv4(),
      engagement_id: scope.engagement_id,
      kind: "llm_call",
      timestamp: new Date().toISOString(),
      node: "worker",
      details: { tier: "worker", subdomain, cache_key: cacheKey },
    });
  } catch (err) {
    context.auditAppend({
      id: uuidv4(),
      engagement_id: scope.engagement_id,
      kind: "error",
      timestamp: new Date().toISOString(),
      node: "worker",
      details: { error: String(err), subdomain },
    });
    return [];
  }

  return classification.findings.map((f) => ({
    id: uuidv4(),
    subdomain,
    category: f.category,
    severity: f.severity,
    evidence: Object.fromEntries(
      f.evidence_keys.map((k) => [k, evidence[k]]),
    ),
    status: "unverified" as const,
    description: f.description,
  }));
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

const WORKER_CLASSIFY_PROMPT = `You are a security analyst classifying recon tool output.

Given subdomain evidence (port scan results, HTTP headers), identify candidate security findings.
Focus on:
- Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Exposed sensitive services (admin panels, unprotected APIs, debug endpoints)
- Outdated software versions with known CVEs
- Misconfigured TLS (no HTTPS, weak ciphers)
- Information disclosure in headers (server version, X-Powered-By)

Return ONLY a JSON object with this exact schema:
{
  "findings": [
    {
      "category": "string (e.g. misconfigured_header, exposed_service, outdated_software)",
      "severity": "low | medium | high | critical",
      "description": "plain-language summary",
      "evidence_keys": ["list of evidence keys relevant to this finding"]
    }
  ]
}

If no findings, return {"findings": []}.
Do not include speculative findings — only flag what the evidence clearly supports.`;

// ---------------------------------------------------------------------------
// Simple non-crypto hash for cache keys
// ---------------------------------------------------------------------------

function hashStr(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  }
  return Math.abs(h).toString(36);
}
