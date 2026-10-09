import { describe, expect, it, jest, beforeEach } from "@jest/globals";

type FetchLike = (url: string, init?: unknown) => Promise<unknown>;
const fetchMock = jest.fn<FetchLike>();
jest.unstable_mockModule("node-fetch", () => ({ default: fetchMock }) as unknown as typeof import("node-fetch"));

const { GreyNoiseClient, GreyNoiseApiError } = await import("./client.js");
const { ipQuickCheckSchema } = await import("./schemas.js");

const ok = (body: unknown) => ({
  ok: true,
  status: 200,
  text: async () => JSON.stringify(body),
  headers: { get: () => null },
});

describe("GreyNoiseClient", () => {
  const client = new GreyNoiseClient("https://api.greynoise.io/", () => "test-key");
  beforeEach(() => {
    fetchMock.mockReset();
  });

  const valid = {
    ip: "1.2.3.4",
    business_service_intelligence: { found: false },
    internet_scanner_intelligence: { found: true, classification: "malicious" },
  };

  it("sends the key header and validates the response", async () => {
    fetchMock.mockResolvedValueOnce(ok(valid));
    const result = await client.get("v3/ip/1.2.3.4", ipQuickCheckSchema, { quick: "true" });
    expect(result.internet_scanner_intelligence.classification).toBe("malicious");
    const [url, init] = fetchMock.mock.calls[0] as [string, { headers: Record<string, string> }];
    expect(url).toContain("v3/ip/1.2.3.4");
    expect(url).toContain("quick=true");
    expect(init.headers.key).toBe("test-key");
  });

  it("throws GreyNoiseApiError on a client error status", async () => {
    fetchMock.mockResolvedValueOnce({ ok: false, status: 403, text: async () => "forbidden", headers: { get: () => null } });
    await expect(client.get("v3/ip/1.2.3.4", ipQuickCheckSchema)).rejects.toBeInstanceOf(GreyNoiseApiError);
  });

  it("keeps the body of a 429 that outlasts its retries", async () => {
    const body = JSON.stringify({ error: "Your searches will reset on October 15." });
    fetchMock.mockResolvedValue({ ok: false, status: 429, text: async () => body, headers: { get: () => null } });
    const error = await client.get("v3/ip/8.8.8.8", ipQuickCheckSchema).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(GreyNoiseApiError);
    expect((error as Error).message).toContain("reset on October 15");
  });

  it("throws when the response fails schema validation", async () => {
    fetchMock.mockResolvedValueOnce(ok({ ip: "1.2.3.4" }));
    await expect(client.get("v3/ip/1.2.3.4", ipQuickCheckSchema)).rejects.toThrow();
  });
});
