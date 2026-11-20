import { initClient, getClient } from "./client";
import { logger } from "@/lib/logger";
import { useAuthStore } from "../../stores/authStore";
import { invoke } from "@tauri-apps/api/core";
import { loadApiCredentials } from "./apiCredentials";
import { logVaultState } from "../runtime/bridge";

/**
 * Attempts to restore a previously saved Telegram session.
 *
 * Session token is stored via a dedicated Rust command (save_session) which
 * writes an encrypted file in the app data dir (see src-tauri/src/secure_store.rs).
 * It survives dev-server restarts.
 *
 * Credentials (API ID / API Hash) are still read from the encrypted vault so
 * users who configure custom credentials retain that preference.
 */
export async function restoreSession(): Promise<boolean> {
  logger.log("restoreSession: Starting session restoration...");
  try {
    // ── 1. Load the session token from the file-backed store ──────────────────
    let sessionString: string | null = null;
    let phoneNumber: string = "";

    try {
      const stored = await invoke<{ session: string | null; phone: string | null }>(
        "load_session"
      );
      sessionString = stored?.session ?? null;
      phoneNumber   = stored?.phone   ?? "";
      const maskedPhone = phoneNumber ? phoneNumber.slice(0, 4) + "****" + phoneNumber.slice(-4) : "empty";
      await logVaultState(
        `RESTORE_LAUNCH: hasSession=${!!sessionString} sessionLen=${sessionString?.length ?? 0} phone=${maskedPhone}`
      );
    } catch (loadErr: any) {
      await logVaultState(
        `RESTORE_LOAD_ERR: ${loadErr?.message ?? JSON.stringify(loadErr)}`
      );
      // If we can't load, fall through and return false
      return false;
    }

    if (!sessionString) {
      await logVaultState("RESTORE_DONE: No session stored.");
      return false;
    }

    // ── 2. Resolve API credentials (vault or built-in defaults) ───────────────
    const { apiId, apiHash } = await loadApiCredentials();

    // Set credentials in Zustand store
    useAuthStore.getState().setCredentials(apiId, apiHash);

    // ── 3. Re-initialise the Telegram client and verify the session ───────────
    await initClient(apiId, apiHash, sessionString);
    const client = getClient();

    const isAuthorized = await client.isUserAuthorized();
    await logVaultState(`RESTORE_AUTH_CHECK: isAuthorized=${isAuthorized}`);

    if (isAuthorized) {
      useAuthStore.getState().setSession(sessionString, phoneNumber);
      await logVaultState("RESTORE_SUCCESS: Session restored successfully.");
      return true;
    } else {
      // Session is stale — clear it so the user is not stuck
      await invoke("clear_session").catch(() => {});
      useAuthStore.getState().logout();
      await logVaultState("RESTORE_FAIL: Session not authorized. Cleared.");
      return false;
    }
  } catch (error: any) {
    const errorStr = `RESTORE_EXC: ${error?.message ?? "no_msg"}\nStack: ${error?.stack ?? "no_stack"}`;
    await logVaultState(errorStr);
    
    // Check if this error is due to a network connection failure (e.g. offline)
    const errorMsg = (error?.message || "").toLowerCase();
    const isNetworkError =
      errorMsg.includes("timeout") ||
      errorMsg.includes("network") ||
      errorMsg.includes("fetch") ||
      errorMsg.includes("connect") ||
      errorMsg.includes("disconnect") ||
      errorMsg.includes("socket") ||
      errorMsg.includes("dns") ||
      errorMsg.includes("resolve") ||
      errorMsg.includes("etimedout") ||
      errorMsg.includes("enotfound") ||
      errorMsg.includes("econnrefused") ||
      errorMsg.includes("handshake");

    if (!isNetworkError) {
      logger.warn("restoreSession: Authentication failure or invalid credentials, clearing session...", error);
      await invoke("clear_session").catch(() => {});
      useAuthStore.getState().logout();
    } else {
      logger.warn("restoreSession: Network connection failure during restoration (offline launch?), keeping session active:", error);
    }
    return false;
  }
}
