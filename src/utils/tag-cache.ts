import type { GreyNoiseClient } from "../greynoise/client.js";
import { tagsListSchema, type Tag } from "../greynoise/schemas/tags.js";

export const CACHE_DURATION_MS = 60 * 60 * 1000;

type TagCache = { timestamp: number; tags: Tag[] };

let tagCache: TagCache | null = null;

export async function getCachedTags(client: GreyNoiseClient): Promise<Tag[]> {
  const now = Date.now();
  if (tagCache && now - tagCache.timestamp < CACHE_DURATION_MS) return tagCache.tags;
  const { tags } = await client.get("v3/tags", tagsListSchema);
  tagCache = { timestamp: now, tags };
  return tags;
}
