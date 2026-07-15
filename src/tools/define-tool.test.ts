import { describe, expect, it } from "@jest/globals";
import { toUserMessage } from "./tool-errors.js";
import { GreyNoiseApiError } from "../greynoise/errors.js";

describe("toUserMessage", () => {
  it("maps 403 to an entitlement message, not a raw error", () => {
    const msg = toUserMessage(new GreyNoiseApiError(403, "v3/workspaces/x/blocklists", "403 forbidden"));
    expect(msg).toContain("Not entitled (403)");
    expect(msg).toContain("plan");
  });

  it("maps 401 to an authentication message", () => {
    const msg = toUserMessage(new GreyNoiseApiError(401, "v3/ip/1.2.3.4", "401"));
    expect(msg).toContain("Authentication failed (401)");
  });

  it("maps 429 to a rate-limit message", () => {
    expect(toUserMessage(new GreyNoiseApiError(429, "v3/gnql", "429"))).toContain("Rate limited (429)");
  });

  it("falls back to a generic message for non-API errors", () => {
    expect(toUserMessage(new Error("boom"))).toBe("Error: boom");
  });
});
