import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import { sessionSchema } from "../greynoise/schemas/sessions.js";
import { formatSession } from "../utils/formatters/sessions.js";

export function registerGetSessionTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "get-session",
    title: "Get Session",
    description:
      "Get full metadata and connection details for a single GreyNoise sensor session by its ID. Returns source/destination IPs and ports, timestamps, byte/packet counts, classification, and any additional enrichment fields.",
    inputSchema: {
      session_id: z.string().min(1).describe("The unique session identifier"),
      scope: z.string().optional().describe("Data scope for the query (default: workspace)"),
    },
    outputSchema: sessionSchema,
    handler: async ({ session_id, scope }, { client }) => {
      const params: Record<string, unknown> = {};
      if (scope) params.scope = scope;
      const data = await client.get(`v3/sessions/${session_id}`, sessionSchema, params);
      return { text: formatSession(data), structured: data };
    },
  });
}
