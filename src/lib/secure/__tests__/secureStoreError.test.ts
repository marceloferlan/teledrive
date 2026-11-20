import { describe, expect, it } from "vitest";
import { isSecureStoreUnavailable } from "../secureStoreError";

describe("isSecureStoreUnavailable", () => {
  it("recognises the bare string Tauri rejects with", () => {
    expect(
      isSecureStoreUnavailable("SECURE_STORE_UNAVAILABLE: keychain denied"),
    ).toBe(true);
  });

  it("recognises an Error that wraps the code", () => {
    expect(
      isSecureStoreUnavailable(new Error("SECURE_STORE_UNAVAILABLE: no entry")),
    ).toBe(true);
  });

  it("ignores unrelated errors and empty values", () => {
    expect(isSecureStoreUnavailable("Vault file is corrupt")).toBe(false);
    expect(isSecureStoreUnavailable(new Error("network timeout"))).toBe(false);
    expect(isSecureStoreUnavailable(undefined)).toBe(false);
    expect(isSecureStoreUnavailable(null)).toBe(false);
  });
});
