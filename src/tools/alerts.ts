import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { GreyNoiseClient } from "../greynoise/client.js";
import { defineTool } from "./define-tool.js";
import {
  alertSchema,
  alertListSchema,
  alertsWrapperSchema,
  testWebhookResponseSchema,
  okSchema,
  deletionResultSchema,
} from "../greynoise/schemas/operational.js";

const wid = z.string().describe("Workspace ID (UUID) that owns the alert");
const aid = z.string().describe("Alert ID (UUID)");
const v2 = (id: string) => `v2/workspaces/${encodeURIComponent(id)}/alerts`;

// v2 alerts have no dedicated enable/disable endpoint — toggle via a full update
// (a partial update would clobber the alert's other fields).
async function setAlertEnabled(client: GreyNoiseClient, workspace_id: string, alert_id: string, enabled: boolean) {
  const path = `${v2(workspace_id)}/${encodeURIComponent(alert_id)}`;
  const a = await client.get(path, alertSchema);
  const body = {
    name: a.name ?? "",
    enabled,
    query_workspace_id: a.query_workspace_id,
    parameters: [{ type: "query", value: a.gnql_query ?? "" }],
    schedule: a.schedule ?? { type: "daily" },
    recipients: (a.recipients ?? []).map((r) => ({ type: r.type, value: r.value })),
  };
  return client.put(path, alertSchema, body);
}

const recipientsSchema = z
  .array(
    z.object({
      type: z.enum(["email", "webhook"]).describe("Delivery channel"),
      value: z.string().describe("Email address, or webhook URL"),
      headers: z.record(z.string(), z.string()).optional().describe("Custom headers for webhook delivery"),
    }),
  )
  .min(1)
  .describe("Where to send alert notifications");

const scheduleSchema = z
  .object({
    type: z.string().describe("Schedule type, e.g. 'daily' or 'weekly'"),
    time_of_day: z.string().optional().describe("Time of day, HH:MM (24h)"),
    day_of_week: z
      .string()
      .optional()
      .describe("Required for 'weekly' schedules, e.g. 'monday'"),
  })
  .describe("When the alert query runs and notifies");

const buildBody = (query: string, name: string, schedule: unknown, recipients: unknown, enabled?: boolean, queryWs?: string) => ({
  name,
  enabled,
  query_workspace_id: queryWs,
  parameters: [{ type: "query", value: query }],
  schedule,
  recipients,
});

export function registerAlertTools(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "create-alert",
    title: "Create Alert",
    description:
      "Create a scheduled alert that runs a GNQL query and notifies recipients (email/webhook) when it matches. Requires a plan entitled to alerts.",
    inputSchema: {
      workspace_id: wid,
      name: z.string().describe("Alert name"),
      query: z.string().describe("GNQL query the alert monitors"),
      schedule: scheduleSchema,
      recipients: recipientsSchema,
      enabled: z.boolean().optional().describe("Whether the alert is active (default: true)"),
      query_workspace_id: z.string().optional().describe("Workspace to run the query against, if different"),
    },
    outputSchema: alertSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
    handler: async ({ workspace_id, name, query, schedule, recipients, enabled, query_workspace_id }, { client }) => {
      const data = await client.post(
        v2(workspace_id),
        alertSchema,
        buildBody(query, name, schedule, recipients, enabled, query_workspace_id),
      );
      return { text: `Created alert "${data.name ?? data.id}" (id: ${data.id}).`, structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "list-alerts",
    title: "List Alerts",
    description: "List the alerts configured in a workspace.",
    inputSchema: { workspace_id: wid },
    outputSchema: alertsWrapperSchema,
    handler: async ({ workspace_id }, { client }) => {
      const alerts = await client.get(v2(workspace_id), alertListSchema);
      return { text: `${alerts.length} alert(s) configured.`, structured: { alerts } };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "get-alert",
    title: "Get Alert",
    description: "Retrieve a single alert's configuration by ID.",
    inputSchema: { workspace_id: wid, alert_id: aid },
    outputSchema: alertSchema,
    handler: async ({ workspace_id, alert_id }, { client }) => {
      const data = await client.get(`${v2(workspace_id)}/${encodeURIComponent(alert_id)}`, alertSchema);
      return { text: `Alert "${data.name ?? data.id}" — enabled: ${data.enabled ?? "?"}.`, structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "update-alert",
    title: "Update Alert",
    description: "Update an alert's query, schedule, recipients, name, or enabled state.",
    inputSchema: {
      workspace_id: wid,
      alert_id: aid,
      name: z.string().describe("Alert name"),
      query: z.string().describe("GNQL query the alert monitors"),
      schedule: scheduleSchema,
      recipients: recipientsSchema,
      enabled: z.boolean().optional().describe("Whether the alert is active"),
      query_workspace_id: z.string().optional().describe("Workspace to run the query against, if different"),
    },
    outputSchema: alertSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    handler: async ({ workspace_id, alert_id, name, query, schedule, recipients, enabled, query_workspace_id }, { client }) => {
      const data = await client.put(
        `${v2(workspace_id)}/${encodeURIComponent(alert_id)}`,
        alertSchema,
        buildBody(query, name, schedule, recipients, enabled, query_workspace_id),
      );
      return { text: `Updated alert "${data.name ?? data.id}".`, structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "delete-alert",
    title: "Delete Alert",
    description: "Permanently delete an alert. This cannot be undone.",
    inputSchema: { workspace_id: wid, alert_id: aid },
    outputSchema: deletionResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
    handler: async ({ workspace_id, alert_id }, { client }) => {
      await client.del(`${v2(workspace_id)}/${encodeURIComponent(alert_id)}`, okSchema);
      return { text: `Deleted alert ${alert_id}.`, structured: { id: alert_id, deleted: true } };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "enable-alert",
    title: "Enable Alert",
    description: "Enable (resume) a previously disabled alert.",
    inputSchema: { workspace_id: wid, alert_id: aid },
    outputSchema: alertSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    handler: async ({ workspace_id, alert_id }, { client }) => {
      const data = await setAlertEnabled(client, workspace_id, alert_id, true);
      return { text: `Enabled alert ${alert_id}.`, structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "disable-alert",
    title: "Disable Alert",
    description: "Disable (pause) an alert without deleting it.",
    inputSchema: { workspace_id: wid, alert_id: aid },
    outputSchema: alertSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    handler: async ({ workspace_id, alert_id }, { client }) => {
      const data = await setAlertEnabled(client, workspace_id, alert_id, false);
      return { text: `Disabled alert ${alert_id}.`, structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "test-alert-webhook",
    title: "Test Alert Webhook",
    description: "Send a test payload to a webhook URL to verify delivery before wiring it to an alert.",
    inputSchema: {
      workspace_id: wid,
      url: z.string().describe("Webhook URL to test"),
      headers: z.record(z.string(), z.string()).optional().describe("Custom headers to send"),
      type: z.string().optional().describe("Webhook type, if applicable"),
    },
    outputSchema: testWebhookResponseSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    handler: async ({ workspace_id, url, headers, type }, { client }) => {
      const data = await client.post(`${v2(workspace_id)}/test-webhook`, testWebhookResponseSchema, {
        url,
        headers,
        type,
      });
      return { text: `Webhook test ${data.success ? "succeeded" : "failed"} (status ${data.status_code ?? "?"}).`, structured: data };
    },
  });
}
