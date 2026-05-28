import { describe, expect, it } from "@jest/globals";
import type { GnqlStatsResponse } from "../types/greynoise-response.js";
import { formatGnqlStats } from "./formatters.js";

describe("formatGnqlStats", () => {
  it("formats v3 adjusted query and operating system fields", () => {
    const data: GnqlStatsResponse = {
      count: 42,
      query: "classification:malicious",
      adjusted_query: "(classification:malicious) last_seen:90d",
      stats: {
        classifications: [{ classification: "malicious", count: 42 }],
        organizations: [],
        countries: [],
        tags: [],
        actors: [],
        operating_systems: [{ operating_system: "Linux", count: 10 }],
      },
    };

    const output = formatGnqlStats(data);

    expect(output).toContain("Adjusted Query: `(classification:malicious) last_seen:90d`");
    expect(output).toContain("- **Linux**: 10 IPs");
  });
});
