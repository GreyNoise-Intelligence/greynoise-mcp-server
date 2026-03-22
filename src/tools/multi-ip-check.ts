import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { MultiIPV3Response } from "../types/greynoise-response.js";
import { postToGreyNoise } from "../utils/fetch.js";
import { formatMultiIPV3 } from "../utils/formatters.js";
import { getApiKey } from "../utils/api-context.js";

export function registerMultiIPCheckTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  server.tool(
    "multi-ip-check",
    "Check multiple IP addresses at once for scanner intelligence and business service classification",
    {
      ips: z.array(z.string().ip()).min(1).max(10000).describe("List of IP addresses to check (max 10,000)"),
    },
    async ({ ips }) => {
      try {
        const apiKey = (() => {
          try {
            return getApiKey();
          } catch {
            return apiKeyGetter();
          }
        })();

        const requestBody = { ips };

        const multiCheckData = await postToGreyNoise<MultiIPV3Response>(
          `v3/ip`,
          apiBase,
          apiKey,
          requestBody,
        );

        const summaryText = formatMultiIPV3(multiCheckData);

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
              text: `Error performing multi IP check: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
