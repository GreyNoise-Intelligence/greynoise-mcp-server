import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { RIOTLookupResponse } from "../types/greynoise-response.js";
import { fetchGreyNoise } from "../utils/fetch.js";

export function registerRiotLookupTool(server: McpServer, apiBase: string, apiKey: string) {
  server.tool(
    "riot-lookup",
    "Check if an IP address belongs to a common business service",
    {
      ip: z.string().ip().describe("IP address to look up"),
    },
    async ({ ip }) => {
      try {
        // Get RIOT information
        const riotData = await fetchGreyNoise<RIOTLookupResponse>(
          `v2/riot/${ip}`,
          apiBase,
          apiKey,
        );

        // Check if the IP is in RIOT
        if (!riotData.riot) {
          return {
            content: [
              {
                type: "text",
                text: `## RIOT Lookup: ${ip}\n\n❌ **${ip}** is not associated with a common business service.`,
              },
            ],
          };
        }

        // Format the response
        const summaryText = `
## RIOT Lookup: ${ip}

🏢 **${ip}** is a common business service.

**Name**: ${riotData.name || 'N/A'}
**Category**: ${riotData.category || 'N/A'}
**Description**: ${riotData.description || 'N/A'}
${riotData.trust_level ? `**Trust Level**: ${riotData.trust_level}` : ''}
${riotData.last_updated ? `**Last Updated**: ${riotData.last_updated}` : ''}

### Services:
${riotData.services && riotData.services.length > 0 
  ? riotData.services.map(service => `- ${service}`).join('\n')
  : '- No specific services listed'}
`;

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
              text: `Error performing RIOT lookup: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}