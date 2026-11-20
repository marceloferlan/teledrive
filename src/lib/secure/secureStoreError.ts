import { toast } from "sonner";
import i18n from "@/i18n";

/** Error prefix the Rust secure store raises when the OS credential store fails. */
const SECURE_STORE_ERROR_CODE = "SECURE_STORE_UNAVAILABLE";

/** `invoke` rejects with a bare string; vault wrappers may wrap it in an Error. */
export function isSecureStoreUnavailable(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err ?? "");
  return message.includes(SECURE_STORE_ERROR_CODE);
}

/**
 * Tells the user that credentials cannot be read or saved. The toast is
 * persistent and keyed, so repeated failures show a single notice.
 */
export function reportSecureStoreUnavailable(): void {
  toast.error(
    i18n.t("drive:secureStore.unavailable", {
      defaultValue:
        "Secure storage is unavailable. TeleDrive could not reach the system keychain, so your login and keys are not being saved. Allow keychain access and restart the app.",
    }),
    { id: SECURE_STORE_ERROR_CODE, duration: Infinity },
  );
}
