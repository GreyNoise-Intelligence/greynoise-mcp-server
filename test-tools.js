#!/usr/bin/env node

/**
 * Simple test script for GreyNoise MCP tools
 *
 * Usage:
 * 1. Build the project: npm run build
 * 2. Run this script: node test-tools.js [tool-name]
 *
 * Parameters:
 * - [tool-name]: Optional. If provided, only tests the specified tool.
 *                If not provided, tests all tools.
 */

import { getGreyNoiseApiKey, getGreyNoiseApiBase } from "./build/utils/api-key.js";
import { fetchGreyNoise, postToGreyNoise } from "./build/utils/fetch.js";

// Get API credentials
const GREYNOISE_API_BASE = getGreyNoiseApiBase();
let GREYNOISE_API_KEY;

try {
  GREYNOISE_API_KEY = getGreyNoiseApiKey();
} catch (error) {
  console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
  console.error("Make sure you have set the GREYNOISE_API_KEY environment variable");
  process.exit(1);
}

// Sample data for testing
const TEST_DATA = {
  ip: "8.8.8.8", // Google's public DNS
  ips: ["8.8.8.8", "1.1.1.1"], // Google and Cloudflare DNS
  tagSlug: "wordpress-supportcandy-sql-injection-cve-2023-1730-attempt", // A common tag that's likely to exist
  cveId: "CVE-2023-38831", // Example CVE
  gnqlQuery: "classification:malicious last_seen:30d", // Example GNQL query
  category: "activity", // Tag category
  days: "30", // Number of days for activity
};

// Define test cases for each API endpoint
const testCases = {
  "ip-context": {
    func: async () => {
      console.log("Testing IP Context endpoint");
      const endpoint = `v2/noise/context/${TEST_DATA.ip}`;
      console.log(`Endpoint: ${endpoint}`);
      return await fetchGreyNoise(endpoint, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
    },
  },
  "quick-check-ip": {
    func: async () => {
      console.log("Testing Quick Check IP endpoint");
      const endpoint = `v2/noise/quick/${TEST_DATA.ip}`;
      console.log(`Endpoint: ${endpoint}`);
      return await fetchGreyNoise(endpoint, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
    },
  },
  "multi-ip-check": {
    func: async () => {
      console.log("Testing Multi IP Check endpoint");
      const endpoint = `v2/noise/multi/quick`;
      console.log(`Endpoint: ${endpoint}`);
      console.log(`POST Data: ${JSON.stringify({ ips: TEST_DATA.ips })}`);
      return await postToGreyNoise(endpoint, GREYNOISE_API_BASE, GREYNOISE_API_KEY, { ips: TEST_DATA.ips });
    },
  },
  "riot-lookup": {
    func: async () => {
      console.log("Testing RIOT Lookup endpoint");
      const endpoint = `v2/riot/${TEST_DATA.ip}`;
      console.log(`Endpoint: ${endpoint}`);
      return await fetchGreyNoise(endpoint, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
    },
  },
  "tag-list": {
    func: async () => {
      console.log("Testing Tag List endpoint");
      const endpoint = "v3/tags";
      console.log(`Endpoint: ${endpoint}`);
      const tagsResponse = await fetchGreyNoise(endpoint, GREYNOISE_API_BASE, GREYNOISE_API_KEY);

      // Format the response similar to the actual implementation
      const result = tagsResponse.tags.map((tag) => ({
        name: tag.name,
        slug: tag.slug,
      }));

      return {
        count: result.length,
        tags: result,
      };
    },
  },
  "tag-details": {
    func: async () => {
      console.log("Testing Tag Details endpoint");
      // Get all tags first
      const allTagsEndpoint = "v3/tags";
      console.log(`Getting all tags from: ${allTagsEndpoint}`);
      const tagsResponse = await fetchGreyNoise(allTagsEndpoint, GREYNOISE_API_BASE, GREYNOISE_API_KEY);

      // Find the specific tag
      const tag = tagsResponse.tags.find(
        (t) => t.slug === TEST_DATA.tagSlug || t.slug === TEST_DATA.tagSlug.toLowerCase(),
      );

      if (!tag) {
        throw new Error(`Tag with slug "${TEST_DATA.tagSlug}" not found`);
      }

      console.log(`Found tag: ${tag.name} (${tag.id})`);
      return tag;
    },
  },
  "tag-activity": {
    func: async () => {
      console.log("Testing Tag Activity endpoint");

      // Get all tags first
      const allTagsEndpoint = "v3/tags";
      console.log(`Getting all tags from: ${allTagsEndpoint}`);
      const tagsResponse = await fetchGreyNoise(allTagsEndpoint, GREYNOISE_API_BASE, GREYNOISE_API_KEY);

      // Find the specific tag
      const tag = tagsResponse.tags.find(
        (t) => t.slug === TEST_DATA.tagSlug || t.slug === TEST_DATA.tagSlug.toLowerCase(),
      );

      if (!tag) {
        throw new Error(`Tag with slug "${TEST_DATA.tagSlug}" not found`);
      }

      console.log(`Found tag: ${tag.name} (${tag.id})`);

      // Now get activity using the correct tag ID
      const daysNum = parseInt(TEST_DATA.days, 10);
      const granularity = daysNum === 1 ? "1h" : "24h";

      const endpoint = `v3/tags/${tag.id}/activity`;
      console.log(`Endpoint: ${endpoint}`);
      console.log(`Parameters: days=${daysNum}, granularity=${granularity}`);

      return await fetchGreyNoise(endpoint, GREYNOISE_API_BASE, GREYNOISE_API_KEY, {
        days: daysNum,
        granularity,
      });
    },
  },
  "trending-tags": {
    func: async () => {
      console.log("Testing Trending Vulnerabilities endpoint");

      // Get trending tags
      const trendingEndpoint = "v3/summary/tags?sort=trending";
      console.log(`Getting trending tags from: ${trendingEndpoint}`);
      const trendingResponse = await fetchGreyNoise(trendingEndpoint, GREYNOISE_API_BASE, GREYNOISE_API_KEY);

      // Get anomalies tags
      const anomaliesEndpoint = "v3/summary/tags?sort=anomalies";
      console.log(`Getting anomalies tags from: ${anomaliesEndpoint}`);
      const anomaliesResponse = await fetchGreyNoise(anomaliesEndpoint, GREYNOISE_API_BASE, GREYNOISE_API_KEY);

      // Combine results
      console.log(
        `Combining results: ${trendingResponse.tags.length} trending tags and ${anomaliesResponse.tags.length} anomalies tags`,
      );

      // Add a source property to each tag
      const formattedTrendingTags = trendingResponse.tags.map((tag) => ({
        ...tag,
        source: "trending",
      }));

      const formattedAnomaliesTags = anomaliesResponse.tags.map((tag) => ({
        ...tag,
        source: "anomalies",
      }));

      return {
        count: formattedTrendingTags.length + formattedAnomaliesTags.length,
        tags: [...formattedTrendingTags, ...formattedAnomaliesTags],
      };
    },
  },
  "gnql-stats": {
    func: async () => {
      console.log("Testing GNQL Stats endpoint");
      const query = encodeURIComponent(TEST_DATA.gnqlQuery);
      const endpoint = `v2/experimental/gnql/stats?query=${query}&count=5`;
      console.log(`Endpoint: ${endpoint}`);
      return await fetchGreyNoise(endpoint, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
    },
  },
  "cve-details": {
    func: async () => {
      console.log("Testing CVE Details endpoint");
      const endpoint = `v1/cve/${TEST_DATA.cveId}`;
      console.log(`Endpoint: ${endpoint}`);
      return await fetchGreyNoise(endpoint, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
    },
  },
};

// Run a specific test
async function runTest(testName) {
  const test = testCases[testName];
  if (!test) {
    console.error(`Test "${testName}" not found`);
    return false;
  }

  console.log(`\n[${"=".repeat(40)}]`);
  console.log(`Running test: ${testName}`);
  console.log(`[${"=".repeat(40)}]`);

  try {
    const startTime = Date.now();
    const result = await test.func();
    const endTime = Date.now();

    console.log(`✅ Test completed in ${endTime - startTime}ms`);

    // Print first part of result to keep output manageable
    const resultStr = JSON.stringify(result, null, 2);
    console.log("Result preview:");
    console.log(resultStr.length > 500 ? resultStr.substring(0, 500) + "... [truncated]" : resultStr);

    return true;
  } catch (error) {
    console.error(`❌ Test failed: ${error.message}`);
    console.error(`API Base: ${GREYNOISE_API_BASE}`);
    console.error(`API Key Length: ${GREYNOISE_API_KEY ? GREYNOISE_API_KEY.length : 0} characters`);
    if (error.stack) {
      console.error(error.stack);
    }
    return false;
  }
}

// Run all tests or a specific test
async function main() {
  console.log("GreyNoise API Test Runner");
  console.log("=".repeat(50));

  // Parse command line arguments
  const args = process.argv.slice(2);
  const specificTest = args[0];

  let succeeded = 0;
  let failed = 0;

  if (specificTest) {
    // Run specific test
    const success = await runTest(specificTest);
    if (success) succeeded++;
    else failed++;
  } else {
    // Run all tests
    console.log(`Running ${Object.keys(testCases).length} tests\n`);

    for (const testName of Object.keys(testCases)) {
      const success = await runTest(testName);
      if (success) succeeded++;
      else failed++;
    }
  }

  // Print summary
  console.log("\n" + "=".repeat(50));
  console.log("Test Summary");
  console.log("-".repeat(50));
  console.log(`Total: ${succeeded + failed}`);
  console.log(`✅ Succeeded: ${succeeded}`);
  console.log(`❌ Failed: ${failed}`);

  process.exit(failed > 0 ? 1 : 0);
}

main().catch((error) => {
  console.error("Unexpected error:", error);
  process.exit(1);
});
