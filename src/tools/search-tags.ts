import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import { tagSearchResultSchema } from "../greynoise/schemas/tags.js";
import { formatTagSearch } from "../utils/formatters/tags.js";
import { getCachedTags } from "../utils/tag-cache.js";

export function registerSearchTagsTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "search-tags",
    title: "Search Tags",
    description:
      "Search GreyNoise tags (client-side over the cached v3/tags list). query substring-matches name/description/slug/label; category and intention are exact (case-insensitive) matches; cve substring-matches associated CVEs. All params optional; omitting all returns every tag.",
    inputSchema: {
      query: z.string().optional().describe("Substring to match in name, description, slug, or label"),
      category: z.string().optional().describe("Exact category match, e.g. 'activity'"),
      intention: z.string().optional().describe("Exact intention match, e.g. 'malicious', 'benign'"),
      cve: z.string().optional().describe("CVE identifier to match against a tag's associated CVEs"),
    },
    outputSchema: tagSearchResultSchema,
    handler: async ({ query, category, intention, cve }, { client }) => {
      let tags = await getCachedTags(client);

      if (query) {
        const q = query.toLowerCase();
        tags = tags.filter(
          (tag) =>
            tag.name.toLowerCase().includes(q) ||
            (tag.description ?? "").toLowerCase().includes(q) ||
            tag.slug.toLowerCase().includes(q) ||
            (tag.label ?? "").toLowerCase().includes(q),
        );
      }
      if (category) {
        const c = category.toLowerCase();
        tags = tags.filter((tag) => (tag.category ?? "").toLowerCase() === c);
      }
      if (intention) {
        const i = intention.toLowerCase();
        tags = tags.filter((tag) => (tag.intention ?? "").toLowerCase() === i);
      }
      if (cve) {
        const v = cve.toLowerCase();
        tags = tags.filter((tag) => (tag.cves ?? []).some((c) => c.toLowerCase() === v || c.toLowerCase().includes(v)));
      }

      return formatTagSearch(tags);
    },
  });
}
