export function truncateList(items: string[], max: number): string {
  if (items.length <= max) return items.join(", ");
  return items.slice(0, max).join(", ") + ` (and ${items.length - max} more)`;
}

export function formatTimestamp(value: unknown): string {
  if (value === undefined || value === null) return "N/A";
  if (typeof value === "number") return new Date(value).toISOString();
  return String(value);
}

function escapeCsvField(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

export function toCsv(headers: string[], rows: string[][]): string {
  const lines = [headers, ...rows].map((row) => row.map(escapeCsvField).join(","));
  return lines.join("\r\n");
}
