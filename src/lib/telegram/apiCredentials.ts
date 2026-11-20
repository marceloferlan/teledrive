import {
  VAULT_KEY_API_HASH,
  VAULT_KEY_API_ID,
  deleteSecret,
  getSecret,
  saveSecret,
} from "@/lib/secure/vault";
import { DEFAULT_API_HASH, DEFAULT_API_ID } from "./config";

export interface ApiCredentials {
  apiId: number;
  apiHash: string;
  /** True when the user supplied their own credentials instead of the built-in ones. */
  isCustom: boolean;
}

const HASH_PATTERN = /^[0-9a-f]{32}$/i;

/** Validates user input: a positive integer API ID and a 32-character hex API hash. */
export function parseApiCredentials(
  idInput: string,
  hashInput: string,
): Pick<ApiCredentials, "apiId" | "apiHash"> | null {
  const id = idInput.trim();
  const hash = hashInput.trim();
  if (!/^\d+$/.test(id) || !HASH_PATTERN.test(hash)) return null;
  const apiId = Number(id);
  if (!Number.isSafeInteger(apiId) || apiId <= 0) return null;
  return { apiId, apiHash: hash.toLowerCase() };
}

/**
 * Credentials to use for Telegram: the user's own pair from the encrypted
 * vault when both halves are valid, otherwise the built-in pair. A half-saved
 * pair is ignored so the two values never come from different sources.
 */
export async function loadApiCredentials(): Promise<ApiCredentials> {
  try {
    const id = await getSecret(VAULT_KEY_API_ID);
    const hash = await getSecret(VAULT_KEY_API_HASH);
    const custom = parseApiCredentials(id ?? "", hash ?? "");
    if (custom) return { ...custom, isCustom: true };
  } catch {
    // Vault unreadable: fall back to the built-in credentials.
  }
  return { apiId: DEFAULT_API_ID, apiHash: DEFAULT_API_HASH, isCustom: false };
}

export async function saveCustomApiCredentials(
  credentials: Pick<ApiCredentials, "apiId" | "apiHash">,
): Promise<void> {
  await saveSecret(VAULT_KEY_API_ID, String(credentials.apiId));
  await saveSecret(VAULT_KEY_API_HASH, credentials.apiHash);
}

export async function resetApiCredentials(): Promise<void> {
  await deleteSecret(VAULT_KEY_API_ID);
  await deleteSecret(VAULT_KEY_API_HASH);
}
