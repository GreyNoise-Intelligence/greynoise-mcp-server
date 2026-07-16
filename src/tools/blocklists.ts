import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import {
  blocklistSchema,
  listBlocklistsSchema,
  blocklistIpsSchema,
  okSchema,
  deletionResultSchema,
} from "../greynoise/schemas/operational.js";

const wid = z.string().optional().describe("Workspace ID (UUID). Defaults to the workspace the API key is bound to.");
const bid = z.string().describe("Blocklist ID (UUID)");
const bl = (id: string) => `v3/workspaces/${encodeURIComponent(id)}/blocklists`;

export function registerBlocklistTools(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "create-blocklist",
    title: "Create Blocklist",
    description:
      "Create a dynamic blocklist from a GNQL query. The blocklist auto-populates with IPs matching the query. Requires a plan entitled to blocklists.",
    inputSchema: {
      workspace_id: wid,
      query: z.string().describe("GNQL query whose matching IPs populate the blocklist"),
      name: z.string().optional().describe("Human-friendly blocklist name"),
      ip_limit: z.number().int().min(1).optional().describe("Max IPs to include"),
      enabled: z.boolean().optional().describe("Whether the blocklist is active (default: true)"),
    },
    outputSchema: blocklistSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
    handler: async ({ workspace_id, query, name, ip_limit, enabled }, { client }) => {
      const ws = workspace_id ?? (await client.workspaceId());
      const data = await client.post(bl(ws), blocklistSchema, { query, name, ip_limit, enabled });
      return { text: `Created blocklist "${data.name ?? data.id}" (id: ${data.id}).`, structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "list-blocklists",
    title: "List Blocklists",
    description: "List the blocklists in a workspace.",
    inputSchema: {
      workspace_id: wid,
      limit: z.number().int().min(1).max(100).optional().describe("Max blocklists to return (1-100)"),
      offset: z.number().int().min(0).optional().describe("Pagination offset"),
    },
    outputSchema: listBlocklistsSchema,
    handler: async ({ workspace_id, limit, offset }, { client }) => {
      const ws = workspace_id ?? (await client.workspaceId());
      const data = await client.get(bl(ws), listBlocklistsSchema, { limit, offset });
      return { text: `${data.blocklists.length} blocklist(s) returned.`, structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "get-blocklist",
    title: "Get Blocklist",
    description: "Retrieve a single blocklist's configuration by ID.",
    inputSchema: { workspace_id: wid, blocklist_id: bid },
    outputSchema: blocklistSchema,
    handler: async ({ workspace_id, blocklist_id }, { client }) => {
      const ws = workspace_id ?? (await client.workspaceId());
      const data = await client.get(`${bl(ws)}/${encodeURIComponent(blocklist_id)}`, blocklistSchema);
      return { text: `Blocklist "${data.name ?? data.id}" — ${data.last_ip_count ?? 0} IPs.`, structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "update-blocklist",
    title: "Update Blocklist",
    description: "Update a blocklist's query, name, IP limit, or enabled state.",
    inputSchema: {
      workspace_id: wid,
      blocklist_id: bid,
      query: z.string().describe("GNQL query whose matching IPs populate the blocklist"),
      name: z.string().optional().describe("Human-friendly blocklist name"),
      ip_limit: z.number().int().min(1).optional().describe("Max IPs to include"),
      enabled: z.boolean().optional().describe("Whether the blocklist is active"),
    },
    outputSchema: blocklistSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    handler: async ({ workspace_id, blocklist_id, query, name, ip_limit, enabled }, { client }) => {
      const ws = workspace_id ?? (await client.workspaceId());
      const data = await client.put(`${bl(ws)}/${encodeURIComponent(blocklist_id)}`, blocklistSchema, {
        query,
        name,
        ip_limit,
        enabled,
      });
      return { text: `Updated blocklist "${data.name ?? data.id}".`, structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "delete-blocklist",
    title: "Delete Blocklist",
    description: "Permanently delete a blocklist. This cannot be undone.",
    inputSchema: { workspace_id: wid, blocklist_id: bid },
    outputSchema: deletionResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
    handler: async ({ workspace_id, blocklist_id }, { client }) => {
      const ws = workspace_id ?? (await client.workspaceId());
      await client.del(`${bl(ws)}/${encodeURIComponent(blocklist_id)}`, okSchema);
      return { text: `Deleted blocklist ${blocklist_id}.`, structured: { id: blocklist_id, deleted: true } };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "get-blocklist-ips",
    title: "Get Blocklist IPs",
    description: "Retrieve the current list of IPs in a blocklist.",
    inputSchema: {
      workspace_id: wid,
      blocklist_id: bid,
      size: z.number().int().min(1).optional().describe("Max IPs to return"),
    },
    outputSchema: blocklistIpsSchema,
    handler: async ({ workspace_id, blocklist_id, size }, { client }) => {
      const ws = workspace_id ?? (await client.workspaceId());
      const data = await client.get(`${bl(ws)}/${encodeURIComponent(blocklist_id)}/ips`, blocklistIpsSchema, { size });
      return { text: `${data.ips.length} IP(s) in blocklist ${blocklist_id}.`, structured: data };
    },
  });
}
