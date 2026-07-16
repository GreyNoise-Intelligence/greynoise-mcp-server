import { z } from "zod";
import { passthrough } from "../schema-helpers.js";

export const blocklistSchema = passthrough({
  id: z.string(),
  workspace_id: z.string().optional(),
  query: z.string().optional(),
  name: z.string().nullable().optional(),
  ip_limit: z.number().nullable().optional(),
  entitlement_level: z.string().optional(),
  enabled: z.boolean().optional(),
  last_ip_count: z.number().optional(),
  query_workspace_id: z.string().optional(),
  token: z.string().optional(),
  created_at: z.string().optional(),
  updated_at: z.string().optional(),
});

export const listBlocklistsSchema = passthrough({
  blocklists: z.array(blocklistSchema),
  total: z.number().optional(),
  limit: z.number().optional(),
  offset: z.number().optional(),
});

export const blocklistIpsSchema = passthrough({ ips: z.array(z.string()) });

const alertParameterSchema = passthrough({ type: z.string(), value: z.string() });
const alertScheduleSchema = passthrough({
  type: z.string().optional(),
  time_of_day: z.string().optional(),
  day_of_week: z.string().optional(),
});
const alertRecipientSchema = passthrough({ type: z.string(), value: z.string() });

export const alertSchema = passthrough({
  id: z.string(),
  name: z.string().optional(),
  type: z.string().optional(),
  workspace_id: z.string().optional(),
  query_workspace_id: z.string().optional(),
  enabled: z.boolean().optional(),
  status: z.string().optional(),
  gnql_query: z.string().optional(),
  parameters: z.array(alertParameterSchema).nullish(),
  schedule: alertScheduleSchema.nullish(),
  recipients: z.array(alertRecipientSchema).nullish(),
  created_at: z.string().optional(),
  updated_at: z.string().optional(),
});

export const alertListSchema = z.array(alertSchema);
export const alertsWrapperSchema = passthrough({ alerts: alertListSchema });
export const testWebhookResponseSchema = passthrough({
  success: z.boolean(),
  status_code: z.number().optional(),
  response_body: z.string().optional(),
});
export const okSchema = passthrough({});
export const deletionResultSchema = passthrough({ id: z.string(), deleted: z.boolean() });
