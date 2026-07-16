#!/usr/bin/env node
// Outside-in validation harness: connects to the MCP server as a black-box MCP client,
// exercises every tool/prompt/resource, and classifies results.
//
//   PASS         tool returned successfully
//   GATED        entitlement/auth denied (403/401) — expected on plans without the feature
//   WARN         empty result / not-found (often fixture-related, not a server bug)
//   SKIPPED      no fixture / prerequisite unavailable
//   FAIL         schema-validation error, protocol error, or crash  <-- gate fails on these
//
// Env:
//   GREYNOISE_API_KEY   required (passed through to the server)
//   MCP_SERVER_CMD      server entry to spawn (default: "node build/index.js")
//   GN_TEST_WORKSPACE   optional; if set, runs create->delete round-trips for write tools there
//   GREYNOISE_API_BASE  optional; forwarded to the server
//
// Exits non-zero if any FAIL.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

if (!process.env.GREYNOISE_API_KEY) {
  console.error("GREYNOISE_API_KEY is required");
  process.exit(2);
}

const [cmd, ...cmdArgs] = (process.env.MCP_SERVER_CMD ?? "node build/index.js").split(" ");
const testWorkspace = process.env.GN_TEST_WORKSPACE;

const results = [];
const record = (kind, name, detail = "") => results.push({ kind, name, detail });

const isGated = (t) => /entitled \(403\)|Authentication failed \(401\)|\b40[13]\b/.test(t);
const isSchemaFail = (t) => /schema validation|invalid_type|"expected":|ZodError|Invalid input/.test(t);

async function callTool(client, name, args, { expectError = false } = {}) {
  try {
    const r = await client.callTool({ name, arguments: args });
    const text = r.content?.find((x) => x.type === "text")?.text ?? "";
    if (r.isError) {
      if (isSchemaFail(text)) return record("FAIL", name, "schema/validation: " + text.slice(0, 160));
      if (isGated(text)) return record("GATED", name);
      if (expectError) return record("PASS", name, "rejected as expected");
      return record("WARN", name, text.slice(0, 120));
    }
    return record("PASS", name, r.structuredContent !== undefined ? "+structured" : "");
  } catch (e) {
    record("FAIL", name, "threw: " + String(e?.message ?? e).slice(0, 160));
    return null;
  }
}

async function main() {
  const transport = new StdioClientTransport({ command: cmd, args: cmdArgs, env: { ...process.env } });
  const client = new Client({ name: "gn-mcp-validator", version: "1.0.0" });
  await client.connect(transport);

  const { tools } = await client.listTools();
  const { prompts } = await client.listPrompts();
  const { resourceTemplates } = await client.listResourceTemplates().catch(() => ({ resourceTemplates: [] }));
  const { resources } = await client.listResources().catch(() => ({ resources: [] }));
  console.log(`Discovered ${tools.length} tools, ${prompts.length} prompts, ${resources.length}+${resourceTemplates.length} resources.\n`);

  // --- discover live fixtures from the server itself ---
  let tagSlug, sessionId;
  const now = new Date(), weekAgo = new Date(now.getTime() - 7 * 864e5);
  const iso = (d) => d.toISOString();
  try {
    const r = await client.callTool({ name: "get-tag-list", arguments: {} });
    tagSlug = JSON.parse(r.content[0].text)?.tags?.[0]?.slug;
  } catch {}
  try {
    const r = await client.callTool({ name: "search-sessions", arguments: { start_time: iso(weekAgo), end_time: iso(now), page_size: 1 } });
    sessionId = JSON.parse(r.structuredContent ? JSON.stringify(r.structuredContent) : "{}")?.data?.[0]?._id;
  } catch {}

  // --- read-tool fixtures ---
  const ip = "8.8.8.8", range = { start_time: iso(weekAgo), end_time: iso(now) };
  const fixtures = {
    "lookup-ip-context": { ip }, "quick-check-ip": { ip }, "multi-ip-check": { ips: [ip, "1.1.1.1"] },
    "gnql-query": { query: "classification:malicious", size: 1 },
    "gnql-metadata-query": { query: "tags:Mirai", size: 2, format: "csv" },
    "gnql-stats": { query: "classification:malicious" },
    "gnql-timeseries": { query: `ip:${ip}` },
    "gnql-timeseries-stats": { query: "classification:malicious", interval: "day" },
    "get-tag-list": {}, "search-tags": { query: "mirai" },
    "get-tag-details": tagSlug ? { id_or_slug: tagSlug } : null,
    "get-tag-activity": tagSlug ? { id_or_slug: tagSlug } : null,
    "analyze-tags-activity": { query: "mirai", days: "1" },
    "get-cve-details": { cve_id: "CVE-2021-44228" }, "get-trending-vulnerabilities": {},
    "search-sessions": { ...range, page_size: 2 }, "session-fields": {},
    "session-counts": { ...range, fields: "classification" },
    "session-connections": { ...range, src_field: "source.ip", dest_field: "destination.ip" },
    "session-timeseries": { ...range }, "session-unique-values": { ...range, field: "source.ip" },
    "get-session": sessionId ? { session_id: sessionId } : null,
    "get-session-pcap": sessionId ? { session_id: sessionId } : null,
    "export-session-data": sessionId ? { session_id: sessionId } : null,
    "export-sessions-pcap": { ...range, size: 1 },
    "bsi-lookup": { ip }, "bsi-bulk-lookup": { ips: [ip] },
    "bsi-trust-stats": {}, "bsi-company-stats": {}, "bsi-category-stats": {},
    "callback-ip-lookup": { ip }, "list-callback-ips": {}, "export-callback-ips": {}, "callback-overview": {},
  };
  const writeTools = new Set([
    "create-blocklist", "update-blocklist", "delete-blocklist",
    "create-alert", "update-alert", "delete-alert", "enable-alert", "disable-alert", "test-alert-webhook",
  ]);

  console.log("── Read tools ──");
  for (const t of tools) {
    if (writeTools.has(t.name)) continue;
    const args = fixtures[t.name];
    if (args === undefined) { record("SKIPPED", t.name, "no fixture"); continue; }
    if (args === null) { record("SKIPPED", t.name, "prerequisite fixture unavailable"); continue; }
    await callTool(client, t.name, args);
  }

  console.log("── Prompts ──");
  const promptArgs = {
    "ip-threat-analysis": { ip }, "cve-analysis": { cve_id: "CVE-2021-44228" },
    "vendor-threat-report": { vendor: "Apache", timeframe: "30" },
    "emerging-threat-report": {},
    "security-posture-assessment": { organization: "Acme", technologies: "Apache, nginx" },
    "threat-hunting": { indicator_type: "ip", indicator_value: ip, environment: "prod" },
  };
  for (const p of prompts) {
    try {
      const r = await client.getPrompt({ name: p.name, arguments: promptArgs[p.name] ?? {} });
      record(r.messages?.length ? "PASS" : "WARN", "prompt:" + p.name);
    } catch (e) { record("FAIL", "prompt:" + p.name, String(e?.message).slice(0, 120)); }
  }

  console.log("── Resources ──");
  const uris = [`greynoise://ip/${ip}`, "greynoise://cve/CVE-2021-44228", ...(tagSlug ? [`greynoise://tag/${tagSlug}`] : []),
    ...resources.map((r) => r.uri)];
  for (const uri of uris) {
    try { const r = await client.readResource({ uri }); record(r.contents?.length ? "PASS" : "WARN", "res:" + uri); }
    catch (e) { const m = String(e?.message); record(isGated(m) ? "GATED" : "FAIL", "res:" + uri, m.slice(0, 120)); }
  }

  console.log("── Write tools (operational) ──");
  if (!testWorkspace) {
    for (const n of writeTools) record("SKIPPED", n, "set GN_TEST_WORKSPACE to a disposable workspace to round-trip writes");
  } else {
    await writeRoundTrip(client, testWorkspace);
  }

  await client.close();
  report();
}

async function writeRoundTrip(client, workspace_id) {
  // Blocklist lifecycle
  let blId;
  try {
    const r = await client.callTool({ name: "create-blocklist", arguments: { workspace_id, query: "classification:malicious", name: "mcp-validate-DELETE-ME", ip_limit: 10 } });
    const text = r.content?.find((x) => x.type === "text")?.text ?? "";
    if (r.isError) { isGated(text) ? record("GATED", "create-blocklist") : record(isSchemaFail(text) ? "FAIL" : "WARN", "create-blocklist", text.slice(0, 120)); }
    else { blId = r.structuredContent?.id; record("PASS", "create-blocklist", "+structured"); }
  } catch (e) { record("FAIL", "create-blocklist", String(e?.message).slice(0, 120)); }
  if (blId) {
    await callTool(client, "get-blocklist", { workspace_id, blocklist_id: blId });
    await callTool(client, "get-blocklist-ips", { workspace_id, blocklist_id: blId });
    await callTool(client, "update-blocklist", { workspace_id, blocklist_id: blId, query: "classification:malicious", enabled: false });
    await callTool(client, "delete-blocklist", { workspace_id, blocklist_id: blId });
  }
  await callTool(client, "list-blocklists", { workspace_id });

  // Alert lifecycle
  let alId;
  try {
    const r = await client.callTool({ name: "create-alert", arguments: { workspace_id, name: "mcp-validate-DELETE-ME", query: "classification:malicious", schedule: { type: "daily", time_of_day: "09:00" }, recipients: [{ type: "email", value: "noreply@greynoise.io" }] } });
    const text = r.content?.find((x) => x.type === "text")?.text ?? "";
    if (r.isError) { isGated(text) ? record("GATED", "create-alert") : record(isSchemaFail(text) ? "FAIL" : "WARN", "create-alert", text.slice(0, 120)); }
    else { alId = r.structuredContent?.id; record("PASS", "create-alert", "+structured"); }
  } catch (e) { record("FAIL", "create-alert", String(e?.message).slice(0, 120)); }
  if (alId) {
    await callTool(client, "get-alert", { workspace_id, alert_id: alId });
    await callTool(client, "disable-alert", { workspace_id, alert_id: alId });
    await callTool(client, "enable-alert", { workspace_id, alert_id: alId });
    await callTool(client, "delete-alert", { workspace_id, alert_id: alId });
  }
  await callTool(client, "list-alerts", { workspace_id });
  await callTool(client, "test-alert-webhook", { workspace_id, url: "https://example.com/greynoise-mcp-validate" });
}

function report() {
  const by = (k) => results.filter((r) => r.kind === k);
  const order = ["FAIL", "WARN", "GATED", "SKIPPED", "PASS"];
  console.log("\n──────── RESULTS ────────");
  for (const r of results.sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind))) {
    const icon = { PASS: "✅", GATED: "🔒", WARN: "⚠️ ", SKIPPED: "⏭️ ", FAIL: "❌" }[r.kind];
    console.log(`${icon} ${r.name}${r.detail ? " — " + r.detail : ""}`);
  }
  const c = Object.fromEntries(order.map((k) => [k, by(k).length]));
  console.log(`\nSUMMARY: ${c.PASS} pass · ${c.GATED} gated · ${c.WARN} warn · ${c.SKIPPED} skipped · ${c.FAIL} fail`);
  if (c.FAIL > 0) { console.error("\n❌ VALIDATION FAILED — do not promote."); process.exit(1); }
  console.log("\n✅ No hard failures. Review warnings before promoting.");
}

main().catch((e) => { console.error("harness error:", e); process.exit(1); });
