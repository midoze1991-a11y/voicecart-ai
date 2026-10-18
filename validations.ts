import { z } from "zod";

/**
 * Validate untrusted webhook data before using it.
 * Keep fields intentionally narrow; adapt the schema to your store's actual payload.
 */
export const webhookSchema = z.object({
  phone_number: z.string().trim().min(7).max(32)
    .regex(/^\+?[0-9().\-\s]+$/, "Invalid phone number format"),
  customer_name: z.string().trim().min(1).max(120).optional(),
  product_name: z.string().trim().min(1).max(200).optional(),
  total_price: z.union([
    z.number().finite().nonnegative(),
    z.string().trim().regex(/^\d{1,10}(\.\d{1,2})?$/)
  ]).optional(),
  currency: z.string().trim().length(3).regex(/^[A-Za-z]{3}$/).optional(),
  order_id: z.union([z.string().trim().max(100), z.number().int().nonnegative()]).optional(),
  store_id: z.string().trim().min(1).max(120).optional(),
  assistant_id: z.string().trim().min(1).max(200).optional()
}).strict();

export type WebhookPayload = z.infer<typeof webhookSchema>;

export const testCallSchema = z.object({
  assistantId: z.string().trim().min(1).max(200),
  phoneNumber: z.string().trim().min(7).max(32)
    .regex(/^\+?[0-9().\-\s]+$/, "Invalid phone number format")
}).strict();