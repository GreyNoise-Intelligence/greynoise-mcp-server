import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SessionResponse } from "../types/greynoise-response.js";
import { fetchGreyNoise } from "../utils/fetch.js";
import { formatSession } from "../utils/formatters.js";
import { getApiKey } from "../utils/api-context.js";

export function registerGetSessionTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  server.tool(
    "get-session",
    "Get full metadata and connection details for a single GreyNoise sensor session by its ID. Returns source/destination IPs and ports, timestamps, byte/packet counts, classification, and any additional enrichment fields.",
    {
      session_id: z.string().min(1).describe("The unique session identifier"),
      scope: z.string().optional().describe("Data scope for the query (default: workspace)"),
    },
    async ({ session_id, scope }) => {
      try {
        const apiKey = (() => {
          try {
            return getApiKey();
          } catch {
            return apiKeyGetter();
          }
        })();

        const params: Record<string, any> = {};
        if (scope) params.scope = scope;

        const sessionData = await fetchGreyNoise<SessionResponse>(
          `v3/sessions/${session_id}`,
          apiBase,
          apiKey,
          params,
        );

        const summaryText = formatSession(sessionData);

        return {
          content: [
            {
              type: "text",
              text: summaryText,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error retrieving session: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
