import React from "react";
import { useI18n } from "@/lib/i18n";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/Alert";
import { Button } from "@/components/ui/Button";

export function AppLayout({ children }: { children: React.ReactNode }) {
  const { lang, setLang, t } = useI18n();

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b bg-card px-4 py-3">
        <div className="mx-auto flex max-w-3xl items-center justify-between">
          <h1 className="text-lg font-bold text-foreground">{t("appTitle")}</h1>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setLang(lang === "en" ? "ru" : "en")}
          >
            {t("langToggle")}
          </Button>
        </div>
      </header>

      {/* Trust banner */}
      <div className="mx-auto w-full max-w-3xl px-4 pt-4">
        <Alert variant="warning">
          <div className="flex gap-3">
            <svg className="mt-0.5 h-5 w-5 shrink-0 text-warning" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M10.29 3.86l-8.6 14.86A1 1 0 002.56 20h18.88a1 1 0 00.87-1.28l-8.6-14.86a1 1 0 00-1.74 0z" />
            </svg>
            <div>
              <AlertTitle>{t("trustBannerTitle")}</AlertTitle>
              <AlertDescription>{t("trustBannerBody")}</AlertDescription>
            </div>
          </div>
        </Alert>
      </div>

      {/* Main */}
      <main className="mx-auto w-full max-w-3xl flex-1 px-4 py-6">
        {children}
      </main>

      {/* Footer */}
      <footer className="border-t py-3 text-center text-xs text-muted-foreground">
        {t("footerNote")}
      </footer>
    </div>
  );
}
