import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Constant-time comparison avoids leaking secret comparisons via timing.
 */
function safeEqual(a: string, b: string): boolean {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return timingSafeEqual(aBuf, bBuf);
}

/**
 * Supports a shared secret header for generic integrations and Shopify's
 * HMAC-SHA256 signature. Shopify's HMAC must be computed over the RAW body.
 */
export function verifyWebhookRequest(input: {
  rawBody: string;
  headers: Headers;
}): boolean {
  const { rawBody, headers } = input;

  const providedSecret = headers.get("x-webhook-secret");
  const configuredSecret = process.env.WEBHOOK_SECRET_KEY;
  if (providedSecret && configuredSecret && safeEqual(providedSecret, configuredSecret)) {
    return true;
  }

  const shopifySignature = headers.get("x-shopify-hmac-sha256");
  const shopifySecret = process.env.SHOPIFY_WEBHOOK_SECRET;
  if (shopifySignature && shopifySecret) {
    const expected = createHmac("sha256", shopifySecret)
      .update(rawBody, "utf8")
      .digest("base64");
    return safeEqual(shopifySignature, expected);
  }

  return false;
}

/**
 * Basic in-memory limiter. On serverless deployments this state is not shared
 * across instances and may reset on cold starts. Use Redis/Vercel KV for production.
 * No PII is stored: only a short-lived hashed bucket key and request count.
 */
const buckets = new Map<string, { count: number; resetAt: number }>();
export function rateLimit(key: string, limit = 20, windowMs = 60_000) {
  const now = Date.now();
  const current = buckets.get(key);
  if (!current || current.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    // Best-effort cleanup to avoid unbounded growth in a long-running process.
    if (buckets.size > 10_000) {
      for (const [bucketKey, bucket] of buckets) {
        if (bucket.resetAt <= now) buckets.delete(bucketKey);
      }
    }
    return { allowed: true, remaining: limit - 1 };
  }
  if (current.count >= limit) return { allowed: false, remaining: 0 };
  current.count += 1;
  return { allowed: true, remaining: limit - current.count };
}

/** Hash IP/store identifiers before using them as limiter keys. */
export function hashRateLimitKey(value: string): string {
  const salt = process.env.WEBHOOK_SECRET_KEY || "development-only-salt";
  return createHmac("sha256", salt).update(value).digest("hex");
}