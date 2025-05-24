import { GreyNoiseTag, GreyNoiseTagsResponse } from "../types/greynoise-response.js";
import { fetchGreyNoise } from "./fetch.js";

// Cache for tag list results
export type TagCache = {
  timestamp: number;
  tags: GreyNoiseTag[];
};

// Cache duration in milliseconds (1 hour)
export const CACHE_DURATION_MS = 60 * 60 * 1000;

// Initialize empty cache
let tagCache: TagCache | null = null;

/**
 * Gets all GreyNoise tags, using cached data if available and not expired
 */
export async function getCachedTags(apiBase: string, apiKey: string): Promise<GreyNoiseTag[]> {
  // Check if we have valid cached data
  const now = Date.now();
  if (tagCache && now - tagCache.timestamp < CACHE_DURATION_MS) {
    return tagCache.tags;
  }

  // No valid cache, fetch from API
  const { tags } = await fetchGreyNoise<GreyNoiseTagsResponse>("v3/tags", apiBase, apiKey);

  // Update cache
  tagCache = {
    timestamp: now,
    tags,
  };

  return tags;
}
