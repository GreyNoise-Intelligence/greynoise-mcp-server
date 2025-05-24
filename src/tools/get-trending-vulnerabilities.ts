//import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { TrendingTagsResponse } from "../types/greynoise-response.js";
import { fetchGreyNoise } from "../utils/fetch.js";
import { formatTrendingTags } from "../utils/formatters.js";
import { getApiKey } from "../utils/api-context.js";

export function registerGetTrendingVulnerabilitiesTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  server.tool(
    "get-trending-vulnerabilities",
    "Get a list of currently trending vulnerability tags and anomalies from GreyNoise",
    {},
    async ({}) => {
      try {
        // Get API key from context or fallback function
        const apiKey = (() => {
          try {
            return getApiKey();
          } catch {
            return apiKeyGetter();
          }
        })();

        // Get trending tags
        const trendingResponse = await fetchGreyNoise<TrendingTagsResponse>(
          "v3/summary/tags?sort=trending",
          apiBase,
          apiKey,
        );

        // Get anomalies tags
        const anomaliesResponse = await fetchGreyNoise<TrendingTagsResponse>(
          "v3/summary/tags?sort=anomalies",
          apiBase,
          apiKey,
        );

        // Combine tags from both responses
        const trendingTags = trendingResponse.tags;
        const anomaliesTags = anomaliesResponse.tags;

        // Add a source property to differentiate the tags
        const formattedTrendingTags = trendingTags.map((tag) => ({
          name: tag.name,
          slug: tag.slug,
          category: tag.category,
          intention: tag.intention,
          cves: tag.cves,
          created_at: tag.created_at,
          score: tag.score,
          source: "trending",
        }));

        const formattedAnomaliesTags = anomaliesTags.map((tag) => ({
          name: tag.name,
          slug: tag.slug,
          category: tag.category,
          intention: tag.intention,
          cves: tag.cves,
          created_at: tag.created_at,
          score: tag.score,
          source: "anomalies",
        }));

        // Combine all tags
        const allTags = [...formattedTrendingTags, ...formattedAnomaliesTags];

        // Format tags for display
        const result = {
          count: allTags.length,
          tags: allTags,
        };

        // Format response for readability
        const formattedResponse = formatTrendingTags(result);

        return {
          content: [
            {
              type: "text",
              text: formattedResponse,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error retrieving trending vulnerabilities and anomalies: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
