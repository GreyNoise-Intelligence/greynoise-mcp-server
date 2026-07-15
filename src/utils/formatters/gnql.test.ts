import { describe, expect, it } from "@jest/globals";
import type { GnqlQuery } from "../../greynoise/schemas/gnql.js";
import { formatGnqlMetadataCsv } from "./gnql.js";

describe("formatGnqlMetadataCsv", () => {
  const data: GnqlQuery = {
    data: [
      {
        ip: "1.2.3.4",
        internet_scanner_intelligence: {
          classification: "malicious",
          actor: "unknown",
          tags: [
            { name: "Mirai", intention: "malicious" },
            { name: "SSH Bruteforcer", intention: "malicious" },
          ],
          metadata: { organization: "Evil, Inc.", source_country: "US" },
          raw_data: { scan: [{ port: 22, protocol: "TCP" }, { port: 23, protocol: "TCP" }] },
        },
        business_service_intelligence: { found: false },
      },
    ],
    request_metadata: { complete: true, query: "classification:malicious" },
  };

  it("emits a header row and one data row per IP", () => {
    const csv = formatGnqlMetadataCsv(data);
    const lines = csv.split("\r\n");
    expect(lines[0]).toBe("ip,classification,actor,organization,source_country,tags,ports,bsi_found,bsi_name,bsi_trust_level");
    expect(lines).toHaveLength(2);
  });

  it("quotes fields containing commas and joins multi-values", () => {
    const row = formatGnqlMetadataCsv(data).split("\r\n")[1];
    expect(row).toContain('"Evil, Inc."');
    expect(row).toContain("Mirai; SSH Bruteforcer");
    expect(row).toContain("22/TCP; 23/TCP");
    expect(row).toContain("1.2.3.4,malicious,unknown,");
    expect(row.endsWith("false,,")).toBe(true);
  });
});
