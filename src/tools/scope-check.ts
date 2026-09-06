/**
 * src/tools/scope-check.ts
 *
 * Scope enforcement — every tool invocation must pass through scopeCheck()
 * before dispatching to a Sandbox. This is defense-in-depth layer #2 (layer #1
 * is the Sandbox network egress allowlist built from the ScopeGrant).
 *
 * Rule: no tool call reaches a Sandbox without a logged, non-silent scope check.
 * Any check that fails throws a ScopeViolationError and is appended to the audit log.
 */

import { ScopeGrant, AuditEntry, AuditEventKind } from "../types/index.js";
import { v4 as uuidv4 } from "uuid";

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

export class ScopeViolationError extends Error {
  constructor(
    public readonly target: string,
    public readonly reason: string,
    public readonly scope: ScopeGrant,
  ) {
    super(`Scope violation: ${reason} (target: ${target})`);
    this.name = "ScopeViolationError";
  }
}

export class EngagementExpiredError extends Error {
  constructor(public readonly engagement_id: string) {
    super(`Engagement ${engagement_id} has expired`);
    this.name = "EngagementExpiredError";
  }
}

// ---------------------------------------------------------------------------
// Scope check helpers
// ---------------------------------------------------------------------------

/**
 * Returns true if `target` (hostname or IP) is within the ScopeGrant.
 * Checks domain list (exact match or subdomain), IP CIDR ranges, and excludes list.
 */
export function isInScope(target: string, scope: ScopeGrant): boolean {
  // Check exclusions first
  for (const ex of scope.excluded) {
    if (domainMatches(target, ex) || target === ex) return false;
  }

  // Check explicit domain list
  for (const domain of scope.domains) {
    if (domainMatches(target, domain)) return true;
  }

  // Check CIDR ranges (if target looks like an IP)
  if (isIPAddress(target)) {
    for (const cidr of scope.ip_ranges) {
      if (ipInCidr(target, cidr)) return true;
    }
  }

  return false;
}

/** true if host is exactly domain or a subdomain of domain */
function domainMatches(host: string, domain: string): boolean {
  // strip trailing dots
  const h = host.replace(/\.$/, "").toLowerCase();
  const d = domain.replace(/\.$/, "").toLowerCase();
  return h === d || h.endsWith(`.${d}`);
}

function isIPAddress(s: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s);
}

/** Naive IPv4 CIDR check — covers the common cases */
function ipInCidr(ip: string, cidr: string): boolean {
  const [range, bits] = cidr.split("/");
  if (!range || bits === undefined) return false;
  const mask = ~((1 << (32 - parseInt(bits, 10))) - 1) >>> 0;
  const ipInt = ipToInt(ip);
  const rangeInt = ipToInt(range);
  return (ipInt & mask) === (rangeInt & mask);
}

function ipToInt(ip: string): number {
  return ip
    .split(".")
    .reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

// ---------------------------------------------------------------------------
// Primary scope-check function
// ---------------------------------------------------------------------------

export interface ScopeCheckResult {
  allowed: boolean;
  audit: AuditEntry;
}

/**
 * Check whether a tool call targeting `target` is permitted by `scope`.
 * Always returns an AuditEntry regardless of outcome — callers append it to
 * the engagement audit log.
 *
 * @throws EngagementExpiredError if scope has expired
 * @throws ScopeViolationError if target is out of scope
 */
export function scopeCheck(
  target: string,
  scope: ScopeGrant,
  node: string,
): ScopeCheckResult {
  const now = new Date().toISOString();

  // 1. Engagement expiry check
  if (new Date(scope.expires_at) < new Date()) {
    const audit = makeAudit(scope.engagement_id, "scope_check_reject", node, {
      target,
      reason: "engagement_expired",
      expires_at: scope.expires_at,
    });
    throw new EngagementExpiredError(scope.engagement_id);
  }

  // 2. Domain / IP scope check
  if (!isInScope(target, scope)) {
    const audit = makeAudit(scope.engagement_id, "scope_check_reject", node, {
      target,
      reason: "out_of_scope",
      domains: scope.domains,
      ip_ranges: scope.ip_ranges,
      excluded: scope.excluded,
    });
    throw new ScopeViolationError(
      target,
      "target is not within the granted scope",
      scope,
    );
  }

  const audit = makeAudit(scope.engagement_id, "scope_check_pass", node, {
    target,
  });
  return { allowed: true, audit };
}

function makeAudit(
  engagement_id: string,
  kind: AuditEventKind,
  node: string,
  details: Record<string, unknown>,
): AuditEntry {
  return {
    id: uuidv4(),
    engagement_id,
    kind,
    timestamp: new Date().toISOString(),
    node,
    details,
  };
}
