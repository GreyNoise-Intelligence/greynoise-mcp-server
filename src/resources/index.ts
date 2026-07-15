import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { GreyNoiseClient } from "../greynoise/client.js";
import { getCachedTags } from "../utils/tag-cache.js";
import { ipContextSchema } from "../greynoise/schemas.js";
import { cveDetailsSchema } from "../greynoise/schemas/cve.js";

const json = (uri: URL, data: unknown) => ({
  contents: [{ uri: uri.href, mimeType: "application/json", text: JSON.stringify(data, null, 2) }],
});

export function registerResources(server: McpServer, apiBase: string, apiKeyGetter: () => string): void {
  const client = new GreyNoiseClient(apiBase, apiKeyGetter);

  server.registerResource(
    "ip",
    new ResourceTemplate("greynoise://ip/{ip}", { list: undefined }),
    { title: "IP context", description: "GreyNoise context for an IP address", mimeType: "application/json" },
    async (uri, { ip }) => json(uri, await client.get(`v3/ip/${encodeURIComponent(String(ip))}`, ipContextSchema)),
  );

  server.registerResource(
    "cve",
    new ResourceTemplate("greynoise://cve/{cveId}", { list: undefined }),
    { title: "CVE details", description: "GreyNoise exploitation details for a CVE", mimeType: "application/json" },
    async (uri, { cveId }) =>
      json(uri, await client.get(`v1/cve/${encodeURIComponent(String(cveId).toUpperCase())}`, cveDetailsSchema)),
  );

  server.registerResource(
    "tag",
    new ResourceTemplate("greynoise://tag/{slug}", {
      list: undefined,
      complete: {
        slug: async (value) => {
          const tags = await getCachedTags(client);
          return tags
            .map((tag) => tag.slug)
            .filter((slug) => slug.startsWith(value))
            .slice(0, 100);
        },
      },
    }),
    { title: "Tag", description: "GreyNoise tag metadata by slug", mimeType: "application/json" },
    async (uri, { slug }) => {
      const tags = await getCachedTags(client);
      const tag = tags.find((candidate) => candidate.slug === slug);
      if (!tag) throw new Error(`Tag not found: ${slug}`);
      return json(uri, tag);
    },
  );
}
