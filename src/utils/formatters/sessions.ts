import { formatTimestamp } from "../format-helpers.js";
import type { Session } from "../../greynoise/schemas/sessions.js";

const SESSION_PROMOTED_FIELDS = new Set([
  "_id", "id",
  "firstPacket", "lastPacket",
  "source", "destination",
  "source.ip", "source.port", "source.bytes", "source.packets",
  "destination.ip", "destination.port", "destination.bytes", "destination.packets",
  "classification",
]);

export function formatSession(data: Session): string {
  const rec = data as Record<string, any>;
  const id = rec._id ?? rec["id"] ?? "unknown";
  const src = rec.source as Record<string, any> | undefined;
  const dst = rec.destination as Record<string, any> | undefined;
  const srcIp = src?.ip ?? rec["source.ip"] ?? "N/A";
  const srcPort = src?.port ?? rec["source.port"] ?? "N/A";
  const dstIp = dst?.ip ?? rec["destination.ip"] ?? "N/A";
  const dstPort = dst?.port ?? rec["destination.port"] ?? "N/A";
  const srcBytes = src?.bytes ?? rec["source.bytes"] ?? 0;
  const srcPackets = src?.packets ?? rec["source.packets"] ?? 0;
  const dstBytes = dst?.bytes ?? rec["destination.bytes"] ?? 0;
  const dstPackets = dst?.packets ?? rec["destination.packets"] ?? 0;
  const classification = rec.classification;
  const firstPacket = rec.firstPacket;
  const lastPacket = rec.lastPacket;

  let response = `# Session: ${id}\n\n`;

  response += `## Connection\n\n`;
  response += `**Source**: ${srcIp}:${srcPort}\n`;
  response += `**Destination**: ${dstIp}:${dstPort}\n`;
  if (classification) response += `**Classification**: ${classification}\n`;
  response += `\n`;

  response += `## Timing\n\n`;
  response += `**First Packet**: ${formatTimestamp(firstPacket)}\n`;
  response += `**Last Packet**: ${formatTimestamp(lastPacket)}\n\n`;

  response += `## Traffic\n\n`;
  response += `| Direction | Bytes | Packets |\n`;
  response += `|--|--|--|\n`;
  response += `| Source | ${Number(srcBytes).toLocaleString()} | ${Number(srcPackets).toLocaleString()} |\n`;
  response += `| Destination | ${Number(dstBytes).toLocaleString()} | ${Number(dstPackets).toLocaleString()} |\n\n`;

  const extraFields = Object.entries(rec).filter(([key]) => !SESSION_PROMOTED_FIELDS.has(key));
  if (extraFields.length > 0) {
    response += `## Additional Fields\n\n`;
    for (const [key, value] of extraFields) {
      const displayValue = typeof value === "object" ? JSON.stringify(value) : String(value);
      response += `**${key}**: ${displayValue}\n`;
    }
    response += `\n`;
  }

  return response;
}
