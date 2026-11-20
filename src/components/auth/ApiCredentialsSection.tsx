import { useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { ChevronDown, ExternalLink, Loader2 } from "lucide-react";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { runtimeOpenUrl } from "@/lib/runtime/bridge";
import {
  isSecureStoreUnavailable,
  reportSecureStoreUnavailable,
} from "@/lib/secure/secureStoreError";
import {
  loadApiCredentials,
  parseApiCredentials,
  resetApiCredentials,
  saveCustomApiCredentials,
  type ApiCredentials,
} from "@/lib/telegram/apiCredentials";

const TELEGRAM_APPS_URL = "https://my.telegram.org/apps";

interface Props {
  credentials: ApiCredentials;
  onChange: (next: ApiCredentials) => void;
}

/**
 * Lets the user keep the built-in Telegram API credentials or sign in with
 * their own. Shown only before a code has been requested, because a pending
 * login is bound to the API ID that started it.
 */
export default function ApiCredentialsSection({ credentials, onChange }: Props) {
  const { t } = useTranslation("auth");
  const [open, setOpen] = useState(false);
  const [idInput, setIdInput] = useState("");
  const [hashInput, setHashInput] = useState("");
  const [invalid, setInvalid] = useState(false);
  const [busy, setBusy] = useState(false);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    try {
      await action();
    } catch (err) {
      if (isSecureStoreUnavailable(err)) reportSecureStoreUnavailable();
      else toast.error(t("apiCredentials.saveFailed"));
    } finally {
      setBusy(false);
    }
  }

  const handleSave = () =>
    run(async () => {
      const parsed = parseApiCredentials(idInput, hashInput);
      if (!parsed) {
        setInvalid(true);
        return;
      }
      setInvalid(false);
      await saveCustomApiCredentials(parsed);
      setIdInput("");
      setHashInput("");
      setOpen(false);
      onChange({ ...parsed, isCustom: true });
      toast.success(t("apiCredentials.saved"));
    });

  const handleUseDefault = () =>
    run(async () => {
      await resetApiCredentials();
      onChange(await loadApiCredentials());
      toast.success(t("apiCredentials.usingDefault"));
    });

  return (
    <div className="pt-1 text-xs">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="mx-auto flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
      >
        <span>
          {credentials.isCustom
            ? t("apiCredentials.activeCustom", { id: credentials.apiId })
            : t("apiCredentials.toggle")}
        </span>
        <ChevronDown
          className={cn("h-3 w-3 transition-transform", open && "rotate-180")}
        />
      </button>

      {open && (
        <div className="mt-2 space-y-2 rounded-xl border border-input p-3 animate-in fade-in duration-200">
          <p className="text-[11px] text-muted-foreground leading-relaxed">
            {t("apiCredentials.help")}
          </p>
          <button
            type="button"
            onClick={() => void runtimeOpenUrl(TELEGRAM_APPS_URL)}
            className="inline-flex items-center gap-1 text-[11px] text-[#0B57D0] dark:text-[#A8C7FA] hover:underline cursor-pointer"
          >
            <span>{t("apiCredentials.openSite")}</span>
            <ExternalLink className="h-3 w-3" />
          </button>

          <Input
            value={idInput}
            onChange={(e) => setIdInput(e.target.value)}
            placeholder={t("apiCredentials.apiIdLabel")}
            aria-label={t("apiCredentials.apiIdLabel")}
            inputMode="numeric"
            autoComplete="off"
            spellCheck={false}
            aria-invalid={invalid}
          />
          <Input
            type="password"
            value={hashInput}
            onChange={(e) => setHashInput(e.target.value)}
            placeholder={t("apiCredentials.apiHashLabel")}
            aria-label={t("apiCredentials.apiHashLabel")}
            autoComplete="off"
            spellCheck={false}
            aria-invalid={invalid}
          />
          {invalid && (
            <p role="alert" className="text-[11px] text-destructive">
              {t("apiCredentials.invalid")}
            </p>
          )}

          <div className="flex gap-2 pt-1">
            <button
              type="button"
              disabled={busy}
              onClick={handleSave}
              className="flex-1 inline-flex items-center justify-center gap-1.5 py-2 rounded-lg bg-[#0B57D0] hover:bg-[#0842A0] dark:bg-[#A8C7FA] dark:text-[#062E6F] text-white font-medium cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {busy && <Loader2 className="h-3 w-3 animate-spin" />}
              <span>{t("apiCredentials.save")}</span>
            </button>
            {credentials.isCustom && (
              <button
                type="button"
                disabled={busy}
                onClick={handleUseDefault}
                className="flex-1 py-2 rounded-lg border border-input text-foreground cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {t("apiCredentials.useDefault")}
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
