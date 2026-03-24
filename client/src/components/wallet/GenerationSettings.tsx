import { useState, useEffect, useRef } from "react";
import { useI18n } from "@/contexts/I18nContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";

interface GenerationSettingsProps {
  onGenerate: (wordCount: 12 | 24, passphrase?: string) => void;
  loading: boolean;
  onBack: () => void;
}

const GenerationSettings = ({ onGenerate, loading, onBack }: GenerationSettingsProps) => {
  const { t } = useI18n();
  const [wordCount, setWordCount] = useState<"12" | "24">("12");
  const [passphrase, setPassphrase] = useState("");
  const [passphraseConfirm, setPassphraseConfirm] = useState("");
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const hasPassphrase = passphrase.length > 0 || passphraseConfirm.length > 0;
  const mismatch = hasPassphrase && passphrase !== passphraseConfirm;
  const canGenerate = !loading && !mismatch;

  const handleSubmit = () => {
    if (!canGenerate) return;
    const pp = passphrase.length > 0 ? passphrase : undefined;
    onGenerate(Number(wordCount) as 12 | 24, pp);
  };

  return (
    <div>
      <h2 ref={headingRef} tabIndex={-1} className="mb-6 text-2xl font-bold text-foreground outline-none">
        {t("genTitle")}
      </h2>

      <div className="mb-6">
        <label className="mb-2 block text-sm font-medium text-foreground">{t("wordCount")}</label>
        <RadioGroup value={wordCount} onValueChange={(v) => setWordCount(v as "12" | "24")} className="flex gap-4">
          <div className="flex items-center gap-2">
            <RadioGroupItem value="12" id="wc-12" />
            <label htmlFor="wc-12" className="cursor-pointer text-sm">{t("words12")}</label>
          </div>
          <div className="flex items-center gap-2">
            <RadioGroupItem value="24" id="wc-24" />
            <label htmlFor="wc-24" className="cursor-pointer text-sm">{t("words24")}</label>
          </div>
        </RadioGroup>
      </div>

      <div className="mb-4">
        <label htmlFor="pp" className="mb-1 block text-sm font-medium text-foreground">
          {t("passphrase")}
        </label>
        <p className="mb-1.5 text-xs text-muted-foreground">{t("passphraseHint")}</p>
        <Input
          id="pp"
          type="password"
          autoComplete="off"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
        />
      </div>

      <div className="mb-6">
        <label htmlFor="pp-confirm" className="mb-1 block text-sm font-medium text-foreground">
          {t("passphraseConfirm")}
        </label>
        <Input
          id="pp-confirm"
          type="password"
          autoComplete="off"
          value={passphraseConfirm}
          onChange={(e) => setPassphraseConfirm(e.target.value)}
        />
        {mismatch && (
          <p className="mt-1 text-sm text-destructive" role="alert" aria-live="assertive">
            {t("passphraseMismatch")}
          </p>
        )}
      </div>

      <div className="flex gap-3">
        <Button variant="outline" onClick={onBack} disabled={loading}>
          {t("back")}
        </Button>
        <Button onClick={handleSubmit} disabled={!canGenerate} className="flex-1">
          {loading ? t("generating") : t("generateWallet")}
        </Button>
      </div>
    </div>
  );
};

export default GenerationSettings;
