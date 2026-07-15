import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import {
  bsiLookupResponseSchema,
  bsiBulkResponseSchema,
  bsiTrustResponseSchema,
  bsiCompanyResponseSchema,
  bsiCategoryResponseSchema,
} from "../greynoise/schemas/bsi.js";
import {
  formatBSILookup,
  formatBSIBulk,
  formatBSITrust,
  formatBSICompany,
  formatBSICategory,
} from "../utils/formatters/bsi.js";

const bsiDate = z
  .string()
  .optional()
  .describe("Snapshot date: 'now' (default, live BSI data) or 'YYYY-MM-DD' for historical data (404 if unavailable)");

export function registerBsiTools(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "bsi-lookup",
    title: "BSI Single-IP Lookup",
    description:
      "Look up Business Service Intelligence provider matches for a single IPv4 address. Returns providers whose CIDRs contain the IP, in ascending precedence order (lower = higher priority). IPv6 is rejected. Requires a BSI license.",
    inputSchema: { ip: z.ipv4().describe("IPv4 address to look up (IPv6 not supported)") },
    outputSchema: bsiLookupResponseSchema,
    handler: async ({ ip }, { client }) => {
      const data = await client.get("v3/bsi/lookup", bsiLookupResponseSchema, { ip });
      return { text: formatBSILookup(data), structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "bsi-bulk-lookup",
    title: "BSI Bulk IP Lookup",
    description:
      "Look up BSI provider matches for up to 1,000 IPv4 addresses. Results preserve request order; any IPv6 address fails the whole request with HTTP 400. Requires a BSI license.",
    inputSchema: {
      ips: z.array(z.ipv4()).min(1).max(1000).describe("IPv4 addresses to look up (1-1000, IPv6 not supported)"),
    },
    outputSchema: bsiBulkResponseSchema,
    handler: async ({ ips }, { client }) => {
      const data = await client.post("v3/bsi/bulk", bsiBulkResponseSchema, { ips });
      return { text: formatBSIBulk(data), structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "bsi-trust-stats",
    title: "BSI Trust-Level Stats",
    description: "Counts of BSI IPs and CIDRs grouped by trust level. Requires BSI entitlements.",
    inputSchema: { date: bsiDate },
    outputSchema: bsiTrustResponseSchema,
    handler: async ({ date }, { client }) => {
      const data = await client.get("v3/bsi/trust", bsiTrustResponseSchema, { date });
      return { text: formatBSITrust(data), structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "bsi-company-stats",
    title: "BSI Company Stats",
    description: "Counts of BSI IPs and CIDRs grouped by company name. Requires BSI entitlements.",
    inputSchema: { date: bsiDate },
    outputSchema: bsiCompanyResponseSchema,
    handler: async ({ date }, { client }) => {
      const data = await client.get("v3/bsi/company", bsiCompanyResponseSchema, { date });
      return { text: formatBSICompany(data), structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "bsi-category-stats",
    title: "BSI Category Stats",
    description: "Counts of BSI IPs and CIDRs grouped by category. Requires BSI entitlements.",
    inputSchema: { date: bsiDate },
    outputSchema: bsiCategoryResponseSchema,
    handler: async ({ date }, { client }) => {
      const data = await client.get("v3/bsi/category", bsiCategoryResponseSchema, { date });
      return { text: formatBSICategory(data), structured: data };
    },
  });
}
