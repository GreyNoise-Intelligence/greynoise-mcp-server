import { describe, expect, it } from "@jest/globals";
import type { CVEDetails } from "../greynoise/schemas/cve.js";
import type { GnqlStats } from "../greynoise/schemas/gnql.js";
import { formatCVEDetails } from "./formatters/cve.js";
import { formatGnqlStats } from "./formatters/gnql.js";

describe("formatGnqlStats", () => {
  it("formats v3 adjusted query and operating system fields", () => {
    const data: GnqlStats = {
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

describe("formatCVEDetails entitlement handling", () => {
  const base: CVEDetails = {
    id: "CVE-2024-3400",
    details: {
      vulnerability_name: "PAN-OS RCE",
      vulnerability_description: "cmd injection",
      cve_cvss_score: 10,
      product: "PAN-OS",
      vendor: "Palo Alto",
      published_to_nist_nvd: true,
    },
    timeline: {
      cve_published_date: "2024-04-12",
      cve_last_updated_date: "2024-04-20",
      first_known_published_date: "2024-04-12",
    },
    exploitation_details: { attack_vector: "NETWORK", exploit_found: true, exploitation_registered_in_kev: true, epss_score: 0.9 },
    exploitation_stats: { number_of_available_exploits: 3, number_of_threat_actors_exploiting_vulnerability: 2, number_of_botnets_exploiting_vulnerability: 1 },
    exploitation_activity: { activity_seen: true, benign_ip_count_1d: 1, benign_ip_count_10d: 2, benign_ip_count_30d: 3, threat_ip_count_1d: 4, threat_ip_count_10d: 5, threat_ip_count_30d: 6 },
  };
  const gated = "access limitation";

  const cases: { name: string; data: CVEDetails; hasStats: boolean; hasActivity: boolean; noted: boolean }[] = [
    { name: "fully entitled", data: base, hasStats: true, hasActivity: true, noted: false },
    { name: "stats only", data: { ...base, exploitation_activity: undefined }, hasStats: true, hasActivity: false, noted: true },
    { name: "activity only", data: { ...base, exploitation_stats: undefined }, hasStats: false, hasActivity: true, noted: true },
    { name: "neither present", data: { ...base, exploitation_stats: undefined, exploitation_activity: undefined }, hasStats: false, hasActivity: false, noted: true },
  ];

  for (const c of cases) {
    it(`${c.name}: renders present sections, flags gaps, never crashes`, () => {
      const output = formatCVEDetails(c.data);
      expect(output).toContain("## Exploitation Details");
      expect(output.includes("## Exploitation Statistics\n")).toBe(c.hasStats);
      expect(output.includes("**Activity Seen by GreyNoise**")).toBe(c.hasActivity);
      expect(output.includes(gated)).toBe(c.noted);
    });
  }
});
