import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import {
  trendingTagsResponseSchema,
  trendingTagsSummarySchema,
  type TrendingTagsResponse,
} from "../greynoise/schemas/cve.js";
import { formatTrendingTags } from "../utils/formatters/cve.js";

function tagsWithSource(response: TrendingTagsResponse, source: string) {
  return response.tags.map((tag) => ({
    name: tag.name,
    slug: tag.slug,
    category: tag.category,
    intention: tag.intention,
    cves: tag.cves,
    created_at: tag.created_at,
    score: tag.score,
    source,
  }));
}

export function registerGetTrendingVulnerabilitiesTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "get-trending-vulnerabilities",
    title: "Get Trending Vulnerabilities",
    description:
      "List currently trending and anomalous GreyNoise vulnerability tags. Takes no parameters. Makes two calls (sort=trending, sort=anomalies) and returns the combined set with a 'source' field per tag plus a total count.",
    inputSchema: {},
    outputSchema: trendingTagsSummarySchema,
    handler: async (_args, { client }) => {
      const trending = await client.get("v3/summary/tags", trendingTagsResponseSchema, { sort: "trending" });
      const anomalies = await client.get("v3/summary/tags", trendingTagsResponseSchema, { sort: "anomalies" });

      const tags = [...tagsWithSource(trending, "trending"), ...tagsWithSource(anomalies, "anomalies")];
      const result = { count: tags.length, tags };
      return { text: formatTrendingTags(result), structured: result };
    },
  });
}
