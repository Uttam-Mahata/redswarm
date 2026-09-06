/**
 * src/index.ts
 *
 * Cloudflare Worker entrypoint — routes HTTP requests to the EngagementAgent DO.
 *
 * URL patterns:
 *   POST /engagements            — create new engagement (gets/creates DO by engagement_id)
 *   *    /engagements/:id/*      — proxy to the specific EngagementAgent DO
 *   GET  /engagements/:id/ws    — WebSocket upgrade (proxied to DO)
 *
 * Also exports ReconSandbox so Cloudflare can register it as a Container.
 */

import { routeAgentRequest } from "agents";
import { EngagementAgent } from "./agent/engagement-agent.js";
import { ReconSandbox } from "./sandbox/recon-sandbox.js";
import type { Env } from "./types/index.js";

export { EngagementAgent, ReconSandbox };

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Route POST /engagements → create engagement, get/create the DO
    if (request.method === "POST" && url.pathname === "/engagements") {
      return handleCreateEngagement(request, env);
    }

    // Route /engagements/:id/* → proxy to the specific EngagementAgent DO
    const match = url.pathname.match(/^\/engagements\/([^/]+)(\/.*)?$/);
    if (match) {
      const engagementId = match[1];
      if (!engagementId) {
        return new Response("Bad engagement ID", { status: 400 });
      }
      return proxyToAgent(request, env, engagementId);
    }

    // Health check
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "ok" }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;

// ---------------------------------------------------------------------------
// Engagement creation — validates scope grant, creates the DO
// ---------------------------------------------------------------------------

async function handleCreateEngagement(
  request: Request,
  env: Env,
): Promise<Response> {
  let body: { scope: unknown; target_domain: unknown };
  try {
    body = await request.json();
  } catch {
    return new Response(
      JSON.stringify({ error: "Invalid JSON body" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  const scope = body.scope as { engagement_id?: string; expires_at?: string };
  if (!scope?.engagement_id) {
    return new Response(
      JSON.stringify({ error: "scope.engagement_id is required" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  // Route to the DO, which handles its own validation
  return proxyToAgent(
    new Request(`${new URL(request.url).origin}/start`, {
      method: "POST",
      body: JSON.stringify(body),
      headers: request.headers,
    }),
    env,
    scope.engagement_id,
  );
}

// ---------------------------------------------------------------------------
// Proxy request to the correct EngagementAgent DO
// ---------------------------------------------------------------------------

async function proxyToAgent(
  request: Request,
  env: Env,
  engagementId: string,
): Promise<Response> {
  const id = env.ENGAGEMENT_AGENT.idFromName(engagementId);
  const stub = env.ENGAGEMENT_AGENT.get(id);
  return stub.fetch(request);
}
