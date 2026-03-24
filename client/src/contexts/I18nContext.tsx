import React, { createContext, useContext, useState, useCallback } from "react";
import { en, type TranslationKey } from "@/i18n/en";
import { ru } from "@/i18n/ru";

type Lang = "en" | "ru";
type Translations = Record<TranslationKey, string>;

interface I18nContextValue {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (key: TranslationKey, vars?: Record<string, string | number>) => string;
}

const dictionaries: Record<Lang, Translations> = { en, ru };

const I18nContext = createContext<I18nContextValue | null>(null);

export const I18nProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [lang, setLang] = useState<Lang>("en");

  const t = useCallback(
    (key: TranslationKey, vars?: Record<string, string | number>) => {
      let str = dictionaries[lang][key] ?? dictionaries.en[key] ?? key;
      if (vars) {
        Object.entries(vars).forEach(([k, v]) => {
          str = str.replace(new RegExp(`\\{${k}\\}`, "g"), String(v));
        });
      }
      return str;
    },
    [lang],
  );

  return <I18nContext.Provider value={{ lang, setLang, t }}>{children}</I18nContext.Provider>;
};

export const useI18n = (): I18nContextValue => {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used within I18nProvider");
  return ctx;
};
