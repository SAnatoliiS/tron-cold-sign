import { describe, expect, it } from "vitest";
import { buildDerivationPath } from "./derivationPath";

describe("buildDerivationPath", () => {
  it("uses TRON coin type 195 and account 0", () => {
    expect(buildDerivationPath(0)).toBe("m/44'/195'/0'/0/0");
    expect(buildDerivationPath(3)).toBe("m/44'/195'/0'/0/3");
  });
});
