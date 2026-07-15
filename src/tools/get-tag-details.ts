import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import { tagSchema } from "../greynoise/schemas/tags.js";
import { formatTagDetails } from "../utils/formatters/tags.js";
import { getCachedTags } from "../utils/tag-cache.js";

export function registerGetTagDetailsTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "get-tag-details",
    title: "Get Tag Details",
    description:
      "Get the full record for a single GreyNoise tag, looked up by exact tag id or slug (slug matched case-insensitively) over the cached v3/tags list.",
    inputSchema: { id_or_slug: z.string().describe("Tag ID or slug to retrieve details for") },
    outputSchema: tagSchema,
    handler: async ({ id_or_slug }, { client }) => {
      const tags = await getCachedTags(client);
      const tag = tags.find(
        (t) => t.id === id_or_slug || t.slug === id_or_slug || t.slug === id_or_slug.toLowerCase(),
      );
      if (!tag) throw new Error(`Tag with ID or slug "${id_or_slug}" not found.`);
      return formatTagDetails(tag);
    },
  });
}
