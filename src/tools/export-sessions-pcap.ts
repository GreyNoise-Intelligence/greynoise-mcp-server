import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { fetchGreyNoiseBinary } from "../utils/fetch.js";
import { getApiKey } from "../utils/api-context.js";
import { tmpdir } from "os";
import { join } from "path";
import { unlink } from "fs/promises";

const PCAP_HEADER_SIZE = 24;

export function registerExportSessionsPcapTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  server.tool(
    "export-sessions-pcap",
    `Export a PCAP file containing packets from multiple GreyNoise sensor sessions matching query criteria. Saves the binary PCAP to a temporary directory and returns the file path. The file can be opened with Wireshark, tshark, or tcpdump.

Use Lucene query syntax to filter sessions (e.g., "destination.port:443", "source.ip:1.2.3.4").`,
    {
      start_time: z.string().describe("Start time for the query range (ISO 8601 format, e.g. 2026-01-01T00:00:00Z)"),
      end_time: z.string().describe("End time for the query range (ISO 8601 format, e.g. 2026-01-07T23:59:59Z)"),
      query: z.string().optional().describe("Lucene query string to filter sessions"),
      size: z.number().optional().default(100).describe("Maximum number of sessions to include (default: 100)"),
      sort_by: z.string().optional().default("lastPacket").describe("Field to sort results by (default: lastPacket)"),
      sort_desc: z.boolean().optional().default(true).describe("Sort in descending order (default: true)"),
      scope: z.string().optional().describe("Data scope for the query (default: workspace)"),
    },
    async ({ start_time, end_time, query, size, sort_by, sort_desc, scope }) => {
      try {
        const apiKey = (() => {
          try {
            return getApiKey();
          } catch {
            return apiKeyGetter();
          }
        })();

        const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
        const outputPath = join(tmpdir(), `sessions-export-${timestamp}.pcap`);

        const params: Record<string, string> = {
          start_time,
          end_time,
          size: String(size),
          sort_by: sort_by!,
          sort_desc: String(sort_desc),
        };
        if (query) params.query = query;
        if (scope) params.scope = scope;

        const { filePath, fileSize } = await fetchGreyNoiseBinary(
          `v3/sessions/export`,
          apiBase,
          apiKey,
          outputPath,
          params,
        );

        if (fileSize <= PCAP_HEADER_SIZE) {
          await unlink(filePath).catch(() => {});
          return {
            content: [
              {
                type: "text",
                text: `No matching sessions found for the given query and time range.\n\n**Time Range**: ${start_time} to ${end_time}${query ? `\n**Query**: ${query}` : ""}`,
              },
            ],
          };
        }

        let text = `# Sessions PCAP Export\n\n`;
        text += `**File**: ${filePath}\n`;
        text += `**Size**: ${fileSize.toLocaleString()} bytes\n`;
        text += `**Time Range**: ${start_time} to ${end_time}\n`;
        if (query) text += `**Query**: ${query}\n`;
        text += `**Max Sessions**: ${size}\n`;
        text += `\nOpen with Wireshark, tshark, or tcpdump for analysis.`;

        return {
          content: [
            {
              type: "text",
              text,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error exporting sessions PCAP: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
