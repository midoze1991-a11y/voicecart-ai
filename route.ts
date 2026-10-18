import { NextRequest, NextResponse } from "next/server";
import { webhookSchema } from "@/lib/validations";
import { hashRateLimitKey, rateLimit, verifyWebhookRequest } from "@/lib/security";

export const runtime = "nodejs";

function jsonError(status: number, error: string) {
  return NextResponse.json({ success: false, error }, { status });
}

export async function POST(request: NextRequest) {
  // Limit request body size before parsing to reduce resource-exhaustion risk.
  const contentLength = Number(request.headers.get("content-length") || "0");
  if (contentLength > 64 * 1024) return jsonError(413, "Payload too large");

  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
  const rateKey = hashRateLimitKey(`webhook:${ip}`);
  const limit = rateLimit(rateKey, 30, 60_000);
  if (!limit.allowed) return jsonError(429, "Too many requests");

  let rawBody = "";
  try {
    rawBody = await request.text();
  } catch {
    return jsonError(400, "Invalid request body");
  }
  if (rawBody.length > 64 * 1024) return jsonError(413, "Payload too large");

  // Verify before trusting or processing the body. Do not log headers or body.
  if (!verifyWebhookRequest({ rawBody, headers: request.headers })) {
    return jsonError(401, "Unauthorized webhook");
  }

  let untrusted: unknown;
  try {
    untrusted = JSON.parse(rawBody);
  } catch {
    return jsonError(400, "Invalid JSON payload");
  }

  const parsed = webhookSchema.safeParse(untrusted);
  if (!parsed.success) {
    // Validation details may contain user input; return a generic error and never log PII.
    return jsonError(400, "Invalid webhook payload");
  }

  const payload = parsed.data;
  const apiKey = process.env.VAPI_API_KEY;
  const assistantId = payload.assistant_id || process.env.VAPI_ASSISTANT_ID;
  if (!apiKey || !assistantId) {
    return jsonError(503, "Voice calling service is not configured");
  }

  const total = payload.total_price === undefined ? "not specified" : String(payload.total_price);
  const currency = payload.currency?.toUpperCase() || "";
  // Keep call variables minimal. Ensure your assistant is configured to use these variables.
  const vapiPayload = {
    assistantId,
    customer: { number: payload.phone_number },
    assistantOverrides: {
      variableValues: {
        customer_name: payload.customer_name || "customer",
        product_name: payload.product_name || "your order",
        total_price: `${total} ${currency}`.trim(),
        order_id: payload.order_id === undefined ? "" : String(payload.order_id)
      }
    }
  };

  try {
    const response = await fetch("https://api.vapi.ai/call/phone", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(vapiPayload),
      signal: AbortSignal.timeout(15_000),
      cache: "no-store"
    });

    if (!response.ok) {
      // Never return upstream body or credentials; it may contain internal details.
      return jsonError(502, "Voice provider could not start the call");
    }

    return NextResponse.json({ success: true, message: "Call triggered successfully" }, { status: 200 });
  } catch {
    return jsonError(502, "Voice provider is temporarily unavailable");
  }
}