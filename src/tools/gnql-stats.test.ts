import { readFileSync } from "fs";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { describe, expect, it } from "@jest/globals";

describe("gnql-stats tool", () => {
  it("uses the v3 stats endpoint", () => {
    const sourcePath = resolve(dirname(fileURLToPath(import.meta.url)), "gnql-stats.ts");
    const source = readFileSync(sourcePath, "utf8");

    expect(source).toContain("`v3/gnql/stats`");
    expect(source).not.toContain("v2/experimental/gnql/stats");
  });
});
