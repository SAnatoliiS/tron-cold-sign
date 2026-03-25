import { useI18n } from "@/contexts/I18nContext";
import { Shield } from "lucide-react";

const Header = () => {
  const { lang, setLang, t } = useI18n();

  return (
    <header className="border-b border-border bg-card px-4 py-3">
      <div className="mx-auto flex max-w-3xl items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 rounded-md bg-primary px-2.5 py-1 text-xs font-bold tracking-wide text-primary-foreground">
            <Shield className="h-3.5 w-3.5" />
            {t("offlineMode")}
          </div>
        </div>
        <button
          onClick={() => setLang(lang === "en" ? "ru" : "en")}
          className="rounded-md border border-border px-3 py-1 text-sm font-medium text-foreground transition-colors hover:bg-muted"
          aria-label="Toggle language"
        >
          {lang === "en" ? "RU" : "EN"}
        </button>
      </div>
      <div className="mx-auto mt-1.5 max-w-3xl">
        <p className="text-xs text-muted-foreground">{t("offlineDisclaimer")}</p>
        <p className="text-xs text-muted-foreground opacity-70">{t("noNetworkNote")}</p>
      </div>
    </header>
  );
};

export default Header;
