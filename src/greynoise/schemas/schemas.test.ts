import { describe, expect, it } from "@jest/globals";
import { ipContextSchema, ipQuickCheckSchema } from "../schemas.js";
import { gnqlStatsSchema } from "./gnql.js";

describe("response schema validation", () => {
  const validContext = {
    ip: "1.2.3.4",
    business_service_intelligence: { found: false },
    internet_scanner_intelligence: {
      classification: "malicious",
      tags: [
        {
          id: "t1",
          slug: "mirai",
          name: "Mirai",
          category: "activity",
          intention: "malicious",
          description: "",
          references: [],
          recommend_block: true,
          cves: [],
          created_at: "2020-01-01",
          updated_at: "2020-01-02",
        },
      ],
    },
  };

  it("parses a valid IP context payload and preserves fields", () => {
    const parsed = ipContextSchema.parse(validContext);
    expect(parsed.ip).toBe("1.2.3.4");
    expect(parsed.internet_scanner_intelligence.classification).toBe("malicious");
    expect(parsed.internet_scanner_intelligence.tags?.[0].name).toBe("Mirai");
  });

  it("tolerates unknown API fields via passthrough", () => {
    const parsed = ipContextSchema.parse({ ...validContext, brand_new_field: 123 }) as Record<string, unknown>;
    expect(parsed.brand_new_field).toBe(123);
  });

  it("rejects a payload missing required fields", () => {
    expect(() => ipQuickCheckSchema.parse({ ip: "1.2.3.4" })).toThrow();
  });

  it("rejects a wrong-typed field", () => {
    const validStats = { count: 5, query: "cve:CVE-2023-6549", stats: {} };
    expect(() => gnqlStatsSchema.parse(validStats)).not.toThrow();
    expect(() => gnqlStatsSchema.parse({ ...validStats, count: "not-a-number" })).toThrow();
  });

  it("parses ISI tags that use `created` and omit `created_at`", () => {
    const payload = {
      ...validContext,
      internet_scanner_intelligence: {
        classification: "malicious",
        tags: [
          {
            id: "t1",
            slug: "favicon-scanner",
            name: "Favicon Scanner",
            category: "activity",
            intention: "unknown",
            description: "",
            references: [],
            recommend_block: false,
            cves: [],
            created: "2026-04-17T00:00:00Z",
            updated_at: "2026-07-16T00:00:00Z",
          },
        ],
      },
    };
    const parsed = ipContextSchema.parse(payload);
    expect(parsed.internet_scanner_intelligence.tags?.[0].name).toBe("Favicon Scanner");
  });

  it("parses gnql stats with null stat buckets", () => {
    const parsed = gnqlStatsSchema.parse({
      count: 1,
      query: "ip:1.2.3.4",
      stats: { actors: null, classifications: null, operating_systems: null },
    });
    expect(parsed.count).toBe(1);
  });
});
