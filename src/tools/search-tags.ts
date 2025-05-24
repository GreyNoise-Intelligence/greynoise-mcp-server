import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { GreyNoiseTag } from "../types/greynoise-response.js";
import { getCachedTags } from "../utils/tag-cache.js";
import { getApiKey } from "../utils/api-context.js";

export function registerSearchTagsTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  server.tool(
    "search-tags",
    "Search GreyNoise Tags by various criteria",
    {
      query: z.string().optional().describe("Optional text to search in name, description, etc."),
      category: z.string().optional().describe("Filter by category (e.g., 'activity')"),
      intention: z.string().optional().describe("Filter by intention (e.g., 'malicious', 'benign')"),
      cve: z.string().optional().describe("Filter by associated CVE identifier"),
    },
    async ({ query, category, intention, cve }) => {
      try {
        // Get API key from context or fallback function
        const apiKey = (() => {
          try {
            return getApiKey();
          } catch {
            return apiKeyGetter();
          }
        })();
        
        // Get tags from cache or API
        const tags = await getCachedTags(apiBase, apiKey);

        // Apply filters
        let filteredTags = tags;

        if (query) {
          const lowerQuery = query.toLowerCase();
          filteredTags = filteredTags.filter(
            (tag: GreyNoiseTag) =>
              tag.name.toLowerCase().includes(lowerQuery) ||
              tag.description.toLowerCase().includes(lowerQuery) ||
              tag.slug.toLowerCase().includes(lowerQuery) ||
              tag.label.toLowerCase().includes(lowerQuery),
          );
        }

        if (category) {
          const lowerCategory = category.toLowerCase();
          filteredTags = filteredTags.filter((tag: GreyNoiseTag) => tag.category.toLowerCase() === lowerCategory);
        }

        if (intention) {
          const lowerIntention = intention.toLowerCase();
          filteredTags = filteredTags.filter((tag: GreyNoiseTag) => tag.intention.toLowerCase() === lowerIntention);
        }

        if (cve) {
          const lowerCve = cve.toLowerCase();
          filteredTags = filteredTags.filter((tag: GreyNoiseTag) =>
            tag.cves.some((c: string) => c.toLowerCase() === lowerCve || c.toLowerCase().includes(lowerCve)),
          );
        }

        // Format the response
        const result = filteredTags.map((tag: GreyNoiseTag) => ({
          id: tag.id,
          name: tag.name,
          slug: tag.slug,
          category: tag.category,
          intention: tag.intention,
          description: tag.description,
          recommend_block: tag.recommend_block,
          cves: tag.cves,
          created_at: tag.created_at,
          references: tag.references,
        }));

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  count: result.length,
                  tags: result,
                },
                null,
                2,
              ),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error searching tags: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}