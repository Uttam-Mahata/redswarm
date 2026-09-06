/**
 * src/sandbox/recon-sandbox.ts
 *
 * Cloudflare Sandbox SDK — isolated tool execution wrapper.
 *
 * Every recon/validation tool call runs in a Cloudflare Sandbox container.
 * Network egress is restricted to in-scope hosts via `allowedHosts` (inherited
 * from the Container base class) — this is the infrastructure-level backstop.
 *
 * Structured tool output (exit code, stdout, stderr, parsed fields) is returned
 * as JSON before it reaches an LLM — keeps classification reliable and cheap.
 *
 * NOTE: Sandbox.exec() returns a ProcessRPCDescriptor (id + pid + capability).
 * To collect text output we open the capability's log stream and decode it.
 */

import { Sandbox, type SandboxCommand } from "@cloudflare/sandbox";
import type { ScopeGrant } from "../types/index.js";

// ---------------------------------------------------------------------------
// Tool result shape
// ---------------------------------------------------------------------------

export interface ToolResult {
  exit_code: number;
  stdout: string;
  stderr: string;
  /** Structured parsed output when the tool supports machine-readable format */
  parsed?: Record<string, unknown>;
  /** Duration of the execution in ms */
  duration_ms: number;
}

// ---------------------------------------------------------------------------
// Internal helper: run a command and collect output
// ---------------------------------------------------------------------------

async function runCommand(
  sandbox: ReconSandbox,
  command: SandboxCommand,
  timeoutMs = 60_000,
): Promise<{ exit_code: number; stdout: string; stderr: string }> {
  const proc = await sandbox.exec(command, { timeout: timeoutMs });

  // Collect log events using the ProcessPullSubscriptionRPC.next() interface
  const logStream = await proc.capability.openLogs({
    replay: true,
    follow: true,
  });

  const stdoutChunks: Uint8Array[] = [];
  const stderrChunks: Uint8Array[] = [];
  const decoder = new TextDecoder();

  // ProcessPullSubscriptionRPC has .next() returning Promise<ReadableStreamReadResult<T>>
  while (true) {
    const { value: event, done } = await logStream.next();
    if (done || !event) break;
    if (event.type === "stdout") stdoutChunks.push(event.data);
    if (event.type === "stderr") stderrChunks.push(event.data);
    if (event.type === "terminal") break; // process ended
  }
  logStream.cancel().catch(() => {}); // cleanup

  const status = await proc.capability.status();
  const exit_code =
    status.state === "exited" ? status.exit.code : 1;

  const stdout = decoder.decode(
    mergeUint8Arrays(stdoutChunks),
  );
  const stderr = decoder.decode(
    mergeUint8Arrays(stderrChunks),
  );

  return { exit_code, stdout, stderr };
}

function mergeUint8Arrays(arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((acc, a) => acc + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

// ---------------------------------------------------------------------------
// ReconSandbox — extends Cloudflare Sandbox base class
// ---------------------------------------------------------------------------

/**
 * ReconSandbox is a Cloudflare Sandbox container registered in wrangler.jsonc.
 * One instance per tool call (destroyed after).
 *
 * Network egress is controlled via the `allowedHosts` property which restricts
 * outbound traffic at the container network level — not just an application check.
 */
export class ReconSandbox extends Sandbox<Env> {
  // Block all internet by default; override per-engagement in configureScopeEgress()
  allowedHosts: string[] = [];
  enableInternet = false;

  /**
   * Set the network egress allowlist from the active ScopeGrant.
   * This configures the container's network policy, not just an application check.
   */
  async configureScopeEgress(scope: ScopeGrant): Promise<void> {
    const allowed = [
      ...scope.domains,
      ...scope.ip_ranges,
    ].filter((h) => !scope.excluded.includes(h));

    this.allowedHosts = allowed;
    await this.setEnvVars({
      SCOPE_ENGAGEMENT_ID: scope.engagement_id,
      SCOPE_DOMAINS: scope.domains.join(","),
    });
  }

  // ---------------------------------------------------------------------------
  // Recon tools
  // ---------------------------------------------------------------------------

  /** Run a port/service scan (nmap) and return structured JSON output */
  async portScan(host: string, scope: ScopeGrant): Promise<ToolResult> {
    await this.configureScopeEgress(scope);
    const start = Date.now();

    const cmd: SandboxCommand = [
      "nmap",
      "-sV",
      "-T4",
      "--top-ports", "100",
      "-oX", "-",
      host,
    ];

    const { exit_code, stdout, stderr } = await runCommand(this, cmd);

    return {
      exit_code,
      stdout,
      stderr,
      parsed: parseNmapXml(stdout),
      duration_ms: Date.now() - start,
    };
  }

  /** Probe HTTP headers and TLS config for a target URL */
  async httpHeaderProbe(url: string, scope: ScopeGrant): Promise<ToolResult> {
    await this.configureScopeEgress(scope);
    const start = Date.now();

    const cmd: SandboxCommand = [
      "curl",
      "-s", "-I", "-L",
      "--max-redirs", "3",
      "--connect-timeout", "10",
      "--max-time", "30",
      url,
    ];

    const { exit_code, stdout, stderr } = await runCommand(this, cmd);

    return {
      exit_code,
      stdout,
      stderr,
      parsed: parseHeaders(stdout),
      duration_ms: Date.now() - start,
    };
  }

  /** Subdomain enumeration — passive by default, active when scope allows */
  async subdomainEnum(domain: string, scope: ScopeGrant): Promise<ToolResult> {
    await this.configureScopeEgress(scope);
    const start = Date.now();

    const cmd: SandboxCommand = scope.allow_active_probing
      ? ["subfinder", "-d", domain, "-json"]
      : ["subfinder", "-d", domain, "-json", "-passive"];

    const { exit_code, stdout, stderr } = await runCommand(this, cmd, 120_000);

    return {
      exit_code,
      stdout,
      stderr,
      parsed: parseSubfinderJson(stdout),
      duration_ms: Date.now() - start,
    };
  }

  // ---------------------------------------------------------------------------
  // Validation PoC tools (non-destructive only)
  // ---------------------------------------------------------------------------

  /** Probe for reflected XSS — injects a benign marker and checks if it appears in response */
  async reflectedXssProbe(
    url: string,
    param: string,
    scope: ScopeGrant,
  ): Promise<ToolResult> {
    await this.configureScopeEgress(scope);
    const start = Date.now();
    const marker = `xss_probe_${Date.now()}`;
    const probeUrl = `${url}?${param}=${marker}`;

    const cmd: SandboxCommand = [
      "curl", "-s", "-L",
      "--max-redirs", "2",
      "--connect-timeout", "10",
      "--max-time", "20",
      probeUrl,
    ];

    const { exit_code, stdout, stderr } = await runCommand(this, cmd);
    const reflected = stdout.includes(marker);

    return {
      exit_code,
      stdout,
      stderr,
      parsed: { reflected, marker, probe_url: probeUrl },
      duration_ms: Date.now() - start,
    };
  }

  /** SSRF callback check — no data exfiltration, only callback to controlled listener */
  async ssrfCallbackProbe(
    url: string,
    param: string,
    canaryUrl: string,
    scope: ScopeGrant,
  ): Promise<ToolResult> {
    await this.configureScopeEgress(scope);
    const start = Date.now();
    const probeUrl = `${url}?${param}=${encodeURIComponent(canaryUrl)}`;

    const cmd: SandboxCommand = [
      "curl", "-s",
      "--max-time", "15",
      probeUrl,
    ];

    const { exit_code, stdout, stderr } = await runCommand(this, cmd);

    return {
      exit_code,
      stdout,
      stderr,
      parsed: { probe_url: probeUrl, canary_url: canaryUrl },
      duration_ms: Date.now() - start,
    };
  }
}

// ---------------------------------------------------------------------------
// Output parsers (structured JSON before LLM)
// ---------------------------------------------------------------------------

function parseNmapXml(xml: string): Record<string, unknown> {
  const ports: Array<{ port: number; protocol: string; service: string; version: string }> = [];
  const portMatches = xml.matchAll(
    /<port protocol="(\w+)" portid="(\d+)">.*?<service name="([^"]*)"[^>]*(?:version="([^"]*)")?/gs,
  );
  for (const m of portMatches) {
    ports.push({
      protocol: m[1] ?? "",
      port: parseInt(m[2] ?? "0", 10),
      service: m[3] ?? "",
      version: m[4] ?? "",
    });
  }
  return { ports };
}

function parseHeaders(raw: string): Record<string, unknown> {
  const headers: Record<string, string> = {};
  for (const line of raw.split("\n")) {
    const idx = line.indexOf(":");
    if (idx > 0) {
      const key = line.slice(0, idx).trim().toLowerCase();
      const value = line.slice(idx + 1).trim();
      headers[key] = value;
    }
  }
  return {
    headers,
    missing_security_headers: [
      "x-frame-options",
      "x-content-type-options",
      "content-security-policy",
      "strict-transport-security",
    ].filter((h) => !(h in headers)),
  };
}

function parseSubfinderJson(raw: string): Record<string, unknown> {
  const subdomains: string[] = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed) as { host?: string };
      if (obj.host) subdomains.push(obj.host);
    } catch {
      // non-JSON line
    }
  }
  return { subdomains };
}

// ---------------------------------------------------------------------------
// Env interface
// ---------------------------------------------------------------------------
interface Env {
  RECON_SANDBOX: unknown;
}
