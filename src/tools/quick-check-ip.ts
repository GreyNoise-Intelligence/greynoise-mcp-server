import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { IPQuickCheckV3Response } from "../types/greynoise-response.js";
import { fetchGreyNoise } from "../utils/fetch.js";
import { formatQuickCheckV3 } from "../utils/formatters.js";
import { getApiKey } from "../utils/api-context.js";

export function registerQuickCheckIPTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  server.tool(
    "quick-check-ip",
    "Get a fast, lightweight check of an IP address from GreyNoise",
    {
      ip: z.string().ip().describe("IP address to look up"),
    },
    async ({ ip }) => {
      try {
        const apiKey = (() => {
          try {
            return getApiKey();
          } catch {
            return apiKeyGetter();
          }
        })();

        const quickCheckData = await fetchGreyNoise<IPQuickCheckV3Response>(
          `v3/ip/${ip}`,
          apiBase,
          apiKey,
          { quick: "true" },
        );

        const summaryText = formatQuickCheckV3(quickCheckData);

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
              text: `Error performing quick IP check: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
