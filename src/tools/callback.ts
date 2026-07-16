import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import {
  callbackIPDetailSchema,
  callbackListIPsSchema,
  callbackOverviewSchema,
} from "../greynoise/schemas/callback.js";
import { passthrough } from "../greynoise/schema-helpers.js";
import { formatCallbackIPDetail, formatCallbackList, formatCallbackOverview } from "../utils/formatters/callback.js";

const filterFields = {
  is_stage_1: z.boolean().optional().describe("true = file was downloaded from this IP (stage 1)"),
  is_stage_2: z.boolean().optional().describe("true = suspected C2 based on VT/sandbox analysis (stage 2)"),
  first_seen_after: z.string().optional().describe("Only IPs first seen after this date (YYYY-MM-DD)"),
  first_seen_before: z.string().optional().describe("Only IPs first seen before this date (YYYY-MM-DD)"),
  last_seen_after: z.string().optional().describe("Only IPs last seen after this date (YYYY-MM-DD)"),
  last_seen_before: z.string().optional().describe("Only IPs last seen before this date (YYYY-MM-DD)"),
  has_files: z.boolean().optional().describe("true = only IPs with malware files; false = only IPs without files"),
  file_type: z.string().optional().describe('File MIME type (e.g. "application/x-executable")'),
  file_name: z.string().optional().describe("File name substring match"),
  file_hash: z.string().optional().describe("File SHA256 hash"),
  scanner_ips: z.array(z.string()).optional().describe("Filter to IPs associated with these scanner IPs"),
  ips: z.array(z.string()).optional().describe("Filter to this specific set of callback IPs"),
};

const exportOutputSchema = passthrough({ ips: z.array(z.string()), count: z.number() });

export function registerCallbackTools(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "callback-ip-lookup",
    title: "Callback IP Lookup",
    description:
      "Look up a single callback/C2 IP: attack stage, scanner associations, RIOT status, geo/network enrichment, and downloaded malware files.",
    inputSchema: { ip: z.string().describe("The callback IP address to look up") },
    outputSchema: callbackIPDetailSchema,
    handler: async ({ ip }, { client }) => {
      const data = await client.get(`v1/callback/ip/${encodeURIComponent(ip)}`, callbackIPDetailSchema);
      return { text: formatCallbackIPDetail(data), structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "list-callback-ips",
    title: "List Callback IPs",
    description:
      "Paginated list of callback/C2 IPs filtered by attack stage, first/last seen date ranges, file attributes, and scanner associations. Dates are YYYY-MM-DD.",
    inputSchema: {
      ...filterFields,
      page: z.number().int().min(0).optional().describe("Zero-indexed page number (default 0)"),
      page_size: z.number().int().min(1).max(100).optional().describe("Results per page, 1-100 (default 20)"),
    },
    outputSchema: callbackListIPsSchema,
    handler: async (args, { client }) => {
      const data = await client.post("v1/callback/ips", callbackListIPsSchema, args);
      return { text: formatCallbackList(data), structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "export-callback-ips",
    title: "Export Callback IPs",
    description:
      "Export callback/C2 IPs matching the filters as a plain list. Same filters as List Callback IPs. Dates are YYYY-MM-DD.",
    inputSchema: { ...filterFields },
    outputSchema: exportOutputSchema,
    handler: async (args, { client }) => {
      const raw = await client.postText("v1/callback/export-ips", args);
      const ips = raw
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
      return { text: `${ips.length} callback IP(s) exported.`, structured: { ips, count: ips.length } };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "callback-overview",
    title: "Callback Overview Statistics",
    description:
      "Aggregate statistics for callback/C2 IPs matching the filters: counts by attack stage, file analysis status, RIOT trust levels, scanner associations, and top threat names. Dates are YYYY-MM-DD.",
    inputSchema: { ...filterFields },
    outputSchema: callbackOverviewSchema,
    handler: async (args, { client }) => {
      const data = await client.post("v1/callback/overview", callbackOverviewSchema, args);
      return { text: formatCallbackOverview(data), structured: data };
    },
  });
}
