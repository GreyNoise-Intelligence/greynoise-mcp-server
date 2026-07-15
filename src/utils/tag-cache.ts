import type { GreyNoiseClient } from "../greynoise/client.js";
import { tagsListSchema, type Tag } from "../greynoise/schemas/tags.js";

export const CACHE_DURATION_MS = 60 * 60 * 1000;

type TagCache = { timestamp: number; tags: Tag[] };

// Keyed by API-key identity so a tag list fetched under one key is never served to another
// (HTTP transport uses a per-request Bearer token).
const caches = new Map<string, TagCache>();

export async function getCachedTags(client: GreyNoiseClient): Promise<Tag[]> {
  const key = client.cacheKey();
  const now = Date.now();
  const hit = caches.get(key);
  if (hit && now - hit.timestamp < CACHE_DURATION_MS) return hit.tags;
  const { tags } = await client.get("v3/tags", tagsListSchema);
  caches.set(key, { timestamp: now, tags });
  return tags;
}
