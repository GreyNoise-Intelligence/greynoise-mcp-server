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
    expect(() => gnqlStatsSchema.parse({ count: "not-a-number" })).toThrow();
  });
});
