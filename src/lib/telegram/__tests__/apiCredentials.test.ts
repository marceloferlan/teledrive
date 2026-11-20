import { beforeEach, describe, expect, it, vi } from "vitest";

const store = vi.hoisted(() => new Map<string, string>());
const vault = vi.hoisted(() => ({
  getSecret: vi.fn(async (key: string) => store.get(key) ?? null),
  saveSecret: vi.fn(async (key: string, value: string) => {
    store.set(key, value);
  }),
  deleteSecret: vi.fn(async (key: string) => {
    store.delete(key);
  }),
}));

vi.mock("@/lib/secure/vault", () => ({
  VAULT_KEY_API_ID: "telegram_api_id",
  VAULT_KEY_API_HASH: "telegram_api_hash",
  ...vault,
}));

import {
  loadApiCredentials,
  parseApiCredentials,
  resetApiCredentials,
  saveCustomApiCredentials,
} from "../apiCredentials";
import { DEFAULT_API_HASH, DEFAULT_API_ID } from "../config";

const HASH = "0123456789abcdef0123456789ABCDEF";

describe("parseApiCredentials", () => {
  it("accepts a numeric id and a 32-character hex hash, normalising case", () => {
    expect(parseApiCredentials(" 12345 ", ` ${HASH} `)).toEqual({
      apiId: 12345,
      apiHash: HASH.toLowerCase(),
    });
  });

  it.each([
    ["", HASH],
    ["abc", HASH],
    ["0", HASH],
    ["-5", HASH],
    ["12.5", HASH],
    ["99999999999999999999", HASH],
    ["12345", ""],
    ["12345", HASH.slice(1)],
    ["12345", `${HASH}0`],
    ["12345", "z".repeat(32)],
  ])("rejects id %j with hash %j", (id, hash) => {
    expect(parseApiCredentials(id, hash)).toBeNull();
  });
});

describe("loadApiCredentials", () => {
  beforeEach(() => {
    store.clear();
    vi.clearAllMocks();
  });

  it("falls back to the built-in credentials when nothing is stored", async () => {
    expect(await loadApiCredentials()).toEqual({
      apiId: DEFAULT_API_ID,
      apiHash: DEFAULT_API_HASH,
      isCustom: false,
    });
  });

  it("uses the stored pair when both halves are valid", async () => {
    store.set("telegram_api_id", "777");
    store.set("telegram_api_hash", HASH.toLowerCase());
    expect(await loadApiCredentials()).toEqual({
      apiId: 777,
      apiHash: HASH.toLowerCase(),
      isCustom: true,
    });
  });

  it("ignores a half-saved or malformed pair instead of mixing sources", async () => {
    store.set("telegram_api_id", "777");
    expect((await loadApiCredentials()).isCustom).toBe(false);
    store.set("telegram_api_hash", "not-a-hash");
    expect((await loadApiCredentials()).isCustom).toBe(false);
  });

  it("falls back to the built-in credentials when the vault cannot be read", async () => {
    vault.getSecret.mockRejectedValueOnce(new Error("SECURE_STORE_UNAVAILABLE"));
    expect((await loadApiCredentials()).isCustom).toBe(false);
  });
});

describe("save and reset", () => {
  beforeEach(() => {
    store.clear();
    vi.clearAllMocks();
  });

  it("round-trips a saved pair and reset returns to the built-in one", async () => {
    await saveCustomApiCredentials({ apiId: 42, apiHash: HASH.toLowerCase() });
    expect(await loadApiCredentials()).toMatchObject({ apiId: 42, isCustom: true });

    await resetApiCredentials();
    expect(store.size).toBe(0);
    expect((await loadApiCredentials()).isCustom).toBe(false);
  });
});
