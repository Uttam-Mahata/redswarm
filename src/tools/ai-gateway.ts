/**
 * src/tools/ai-gateway.ts
 *
 * Workers AI client — all LLM calls in redswarm run on Cloudflare Workers AI
 * via the native `AI` binding. No external API keys or providers.
 *
 * Responsibilities:
 * - Model tiering: Worker classification → fast/cheap, Validator/Report → strong
 * - Per-isolate response cache so repeated identical (tool-output → classification)
 *   pairs skip inference
 */

export type ModelTier = "worker" | "validator" | "report";

export interface LLMConfig {
  /** Workers AI binding (wrangler.jsonc: "ai": { "binding": "AI" }) */
  ai: Ai;
  worker_model: string;
  validator_model: string;
  report_model: string;
}

export interface LLMMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

// ---------------------------------------------------------------------------
// Model selection by tier
// ---------------------------------------------------------------------------

export function modelForTier(tier: ModelTier, config: LLMConfig): string {
  switch (tier) {
    case "worker":
      return config.worker_model; // fast/cheap e.g. @cf/meta/llama-3.1-8b-instruct
    case "validator":
      return config.validator_model; // strong e.g. @cf/meta/llama-3.1-70b-instruct
    case "report":
      return config.report_model; // strong e.g. @cf/meta/llama-3.1-70b-instruct
  }
}

// ---------------------------------------------------------------------------
// Per-isolate response cache (bounded)
// ---------------------------------------------------------------------------

const _cache = new Map<string, LLMCallResult>();
const CACHE_MAX_ENTRIES = 128;

function cacheGet(key: string): LLMCallResult | undefined {
  const hit = _cache.get(key);
  if (hit) {
    // LRU refresh
    _cache.delete(key);
    _cache.set(key, hit);
  }
  return hit;
}

function cacheSet(key: string, value: LLMCallResult): void {
  if (_cache.size >= CACHE_MAX_ENTRIES) {
    const oldest = _cache.keys().next().value;
    if (oldest !== undefined) _cache.delete(oldest);
  }
  _cache.set(key, value);
}

// ---------------------------------------------------------------------------
// Primary LLM call helper
// ---------------------------------------------------------------------------

export interface LLMCallOptions {
  tier: ModelTier;
  config: LLMConfig;
  messages: LLMMessage[];
  /** Optional cache key — identical requests short-circuit to cached result */
  cacheKey?: string;
  /** engagement_id used for audit log enrichment */
  engagement_id: string;
  /** LangGraph node name — included in audit metadata */
  node: string;
  /** Max tokens for the response */
  max_tokens?: number;
  /** Response format (JSON mode is prompted; output is always parsed leniently) */
  response_format?: "json_object" | "text";
}

export interface LLMCallResult {
  content: string;
  model: string;
  usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
}

/** Shape returned by Workers AI text-generation models */
interface WorkersAIChatResult {
  response?: string;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
  };
}

export async function callLLM(opts: LLMCallOptions): Promise<LLMCallResult> {
  const model = modelForTier(opts.tier, opts.config);

  if (opts.cacheKey) {
    const cached = cacheGet(opts.cacheKey);
    if (cached) return cached;
  }

  const messages = opts.messages.map((m) => ({
    role: m.role,
    content:
      opts.response_format === "json_object"
        ? `${m.content}\n\nRespond with a single valid JSON object only. No markdown, no code fences, no commentary.`
        : m.content,
  }));

  const result = (await opts.config.ai.run(model, {
    messages,
    max_tokens: opts.max_tokens ?? 2048,
  })) as WorkersAIChatResult;

  const out: LLMCallResult = {
    content: result.response ?? "",
    model,
    usage: {
      prompt_tokens: result.usage?.prompt_tokens ?? 0,
      completion_tokens: result.usage?.completion_tokens ?? 0,
      total_tokens: result.usage?.total_tokens ?? 0,
    },
  };

  if (opts.cacheKey) cacheSet(opts.cacheKey, out);
  return out;
}

// ---------------------------------------------------------------------------
// Structured JSON extraction helper
// ---------------------------------------------------------------------------

/**
 * Call LLM and parse the result as JSON.
 * Falls back to regex extraction if the JSON is wrapped in markdown code fences.
 */
export async function callLLMJson<T>(
  opts: Omit<LLMCallOptions, "response_format">,
): Promise<T> {
  const result = await callLLM({ ...opts, response_format: "json_object" });

  let text = result.content.trim();
  // Strip markdown code fences if present
  text = text.replace(/^```(?:json)?\n?/i, "").replace(/\n?```$/, "");

  return JSON.parse(text) as T;
}
