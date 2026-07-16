import type {
  BSILookupResponse,
  BSIBulkResponse,
  BSITrustResponse,
  BSICompanyResponse,
  BSICategoryResponse,
} from "../../greynoise/schemas/bsi.js";

export function formatBSILookup(data: BSILookupResponse): string {
  const matches = data.matches ?? [];
  if (matches.length === 0) return `# BSI: ${data.ip ?? "?"}\n\nNot in BSI (no provider matches).`;
  let out = `# BSI: ${data.ip ?? "?"}\n\n${matches.length} provider match(es), ascending precedence:\n\n`;
  for (const m of matches) {
    out += `- **${m.name ?? "?"}** (${m.category ?? "?"}) — trust ${m.trust_level ?? "?"}, cidr ${m.cidr ?? "?"}, precedence ${m.precedence ?? "?"}\n`;
  }
  return out;
}

export function formatBSIBulk(data: BSIBulkResponse): string {
  const results = data.results ?? [];
  const hits = results.filter((r) => (r.matches ?? []).length > 0).length;
  let out = `# BSI Bulk Lookup\n\n${results.length} IP(s), ${hits} with matches:\n\n`;
  for (const r of results) {
    const names = (r.matches ?? []).map((m) => m.name ?? "?").join(", ");
    out += `- ${r.ip ?? "?"}: ${names || "no match"}\n`;
  }
  return out;
}

export function formatBSITrust(data: BSITrustResponse): string {
  const rows = data.stats?.trust_levels ?? [];
  let out = `# BSI Trust Stats (date: ${data.date ?? "?"}, source: ${data.source ?? "?"})\n\n`;
  for (const r of rows) {
    out += `- trust ${r.trust_level ?? "?"}: ${r.ip_count ?? 0} IPs, ${r.cidr_count ?? 0} CIDRs\n`;
  }
  return out;
}

export function formatBSICompany(data: BSICompanyResponse): string {
  const rows = data.stats?.companies ?? [];
  let out = `# BSI Company Stats (date: ${data.date ?? "?"}, source: ${data.source ?? "?"})\n\n${rows.length} companies:\n\n`;
  for (const r of rows) {
    out += `- **${r.name ?? "?"}** (${r.category ?? "?"}, trust ${r.trust_level ?? "?"}): ${r.ip_count ?? 0} IPs, ${r.cidr_count ?? 0} CIDRs\n`;
  }
  return out;
}

export function formatBSICategory(data: BSICategoryResponse): string {
  const rows = data.stats?.categories ?? [];
  let out = `# BSI Category Stats (date: ${data.date ?? "?"}, source: ${data.source ?? "?"})\n\n`;
  for (const r of rows) {
    out += `- ${r.category ?? "?"}: ${r.ip_count ?? 0} IPs, ${r.cidr_count ?? 0} CIDRs\n`;
  }
  return out;
}
