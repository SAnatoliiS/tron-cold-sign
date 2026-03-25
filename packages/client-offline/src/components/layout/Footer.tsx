import { useI18n } from "@/contexts/I18nContext";

const Footer = () => {
  const { t } = useI18n();

  return (
    <footer className="border-t border-border bg-card px-4 py-6">
      <div className="mx-auto max-w-3xl">
        <h2 className="mb-2 text-sm font-semibold text-foreground">{t("tailsTitle")}</h2>
        <ul className="space-y-1 text-xs text-muted-foreground">
          <li>• {t("tailsLine1")}</li>
          <li>• {t("tailsLine2")}</li>
          <li>• {t("tailsLine3")}</li>
          <li>• {t("tailsLine4")}</li>
          <li>• {t("tailsLine5")}</li>
        </ul>
      </div>
    </footer>
  );
};

export default Footer;
