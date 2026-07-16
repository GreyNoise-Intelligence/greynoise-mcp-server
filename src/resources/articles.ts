import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { GreyNoiseClient } from "../greynoise/client.js";
import {
  articleSchema,
  articleCategoriesSchema,
  listArticlesResponseSchema,
} from "../greynoise/schemas/articles.js";

const json = (uri: URL, data: unknown) => ({
  contents: [{ uri: uri.href, mimeType: "application/json", text: JSON.stringify(data, null, 2) }],
});

export function registerArticleResources(server: McpServer, apiBase: string, apiKeyGetter: () => string): void {
  const client = new GreyNoiseClient(apiBase, apiKeyGetter);

  server.registerResource(
    "articles",
    "greynoise://articles",
    {
      title: "Articles",
      description: "Paginated list of published GreyNoise research articles (Threat Briefs).",
      mimeType: "application/json",
    },
    async (uri) => json(uri, await client.get("v3/articles", listArticlesResponseSchema)),
  );

  server.registerResource(
    "article-categories",
    "greynoise://article-categories",
    {
      title: "Article categories",
      description: "Available GreyNoise article (Threat Brief) categories.",
      mimeType: "application/json",
    },
    async (uri) => json(uri, await client.get("v3/articles/categories", articleCategoriesSchema)),
  );

  server.registerResource(
    "article",
    new ResourceTemplate("greynoise://article/{id}", { list: undefined }),
    { title: "Article", description: "A single GreyNoise article (Threat Brief) by UUID.", mimeType: "application/json" },
    async (uri, { id }) =>
      json(uri, await client.get(`v3/articles/${encodeURIComponent(String(id))}`, articleSchema)),
  );
}
