import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { GreyNoiseTag } from "../types/greynoise-response.js";
import { getCachedTags } from "../utils/tag-cache.js";

export function registerGetTagDetailsTool(server: McpServer, apiBase: string, apiKey: string) {
  server.tool(
    "get-tag-details",
    "Get detailed information about a specific GreyNoise tag",
    {
      id_or_slug: z.string().describe("Tag ID or slug to retrieve details for"),
    },
    async ({ id_or_slug }) => {
      try {
        // Get tags from cache or API
        const tags = await getCachedTags(apiBase, apiKey);

        // Find matching tag
        const tag = tags.find(
          (t: GreyNoiseTag) => t.id === id_or_slug || t.slug === id_or_slug || t.slug === id_or_slug.toLowerCase(),
        );

        if (!tag) {
          return {
            content: [
              {
                type: "text",
                text: `Tag with ID or slug "${id_or_slug}" not found.`,
              },
            ],
            isError: true,
          };
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(tag, null, 2),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error retrieving tag details: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}