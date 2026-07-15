import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import { tagListResultSchema } from "../greynoise/schemas/tags.js";
import { formatTagList } from "../utils/formatters/tags.js";
import { getCachedTags } from "../utils/tag-cache.js";

export function registerGetTagListTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "get-tag-list",
    title: "Get Tag List",
    description:
      "Retrieve the complete list of GreyNoise tags (from v3/tags, cached 1h). Returns JSON with count and each tag's name and slug. Takes no parameters.",
    inputSchema: {},
    outputSchema: tagListResultSchema,
    handler: async (_args, { client }) => formatTagList(await getCachedTags(client)),
  });
}
