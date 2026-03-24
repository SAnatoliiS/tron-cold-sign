import { useState, useEffect, useRef } from "react";
import { useI18n } from "@/contexts/I18nContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { buildDerivationPath } from "@/lib/derivationPath";

interface SigningStepProps {
  onSign: (mnemonic: string, passphrase: string | undefined, derivationPath: string) => void;
  loading: boolean;
  onBack: () => void;
}

const MAX_INDEX = 99;

const SigningStep = ({ onSign, loading, onBack }: SigningStepProps) => {
  const { t } = useI18n();
  const [mnemonic, setMnemonic] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [indexStr, setIndexStr] = useState("0");
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const parsedIndex = parseInt(indexStr, 10);
  const indexValid = !isNaN(parsedIndex) && Number.isInteger(parsedIndex) && parsedIndex >= 0 && parsedIndex <= MAX_INDEX;
  const mnemonicTrimmed = mnemonic.trim();
  const canSign = mnemonicTrimmed.length > 0 && indexValid && !loading;

  const handleSign = () => {
    if (!canSign) return;
    const dp = buildDerivationPath(parsedIndex);
    const pp = passphrase.length > 0 ? passphrase : undefined;
    onSign(mnemonicTrimmed, pp, dp);
  };

  const derivationPreview = indexValid ? buildDerivationPath(parsedIndex) : "—";

  return (
    <div>
      <h2 ref={headingRef} tabIndex={-1} className="mb-6 text-2xl font-bold text-foreground outline-none">
        {t("signingTitle")}
      </h2>

      <div className="mb-4">
        <label htmlFor="mnemonic" className="mb-1 block text-sm font-medium text-foreground">
          {t("mnemonicLabel")}
        </label>
        <Input
          id="mnemonic"
          type="password"
          autoComplete="off"
          placeholder={t("mnemonicPlaceholder")}
          value={mnemonic}
          onChange={(e) => setMnemonic(e.target.value)}
        />
        {mnemonicTrimmed.length === 0 && mnemonic.length > 0 && (
          <p className="mt-1 text-sm text-destructive" role="alert" aria-live="assertive">
            {t("mnemonicRequired")}
          </p>
        )}
      </div>

      <div className="mb-4">
        <label htmlFor="sign-pp" className="mb-1 block text-sm font-medium text-foreground">
          {t("passphraseLabel")}
        </label>
        <Input
          id="sign-pp"
          type="password"
          autoComplete="off"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
        />
      </div>

      <div className="mb-2">
        <label htmlFor="addr-idx" className="mb-1 block text-sm font-medium text-foreground">
          {t("addressIndex")}
        </label>
        <p className="mb-1.5 text-xs text-muted-foreground">{t("addressIndexHint")}</p>
        <Input
          id="addr-idx"
          type="number"
          min={0}
          max={MAX_INDEX}
          step={1}
          autoComplete="off"
          value={indexStr}
          onChange={(e) => setIndexStr(e.target.value)}
          className="max-w-[8rem]"
        />
        {indexStr.length > 0 && !indexValid && (
          <p className="mt-1 text-sm text-destructive" role="alert" aria-live="assertive">
            {t("invalidIndex")}
          </p>
        )}
      </div>

      <div className="mb-6 text-xs text-muted-foreground">
        {t("derivationPath")}: <span className="font-mono">{derivationPreview}</span>
      </div>

      <div className="flex gap-3">
        <Button variant="outline" onClick={onBack} disabled={loading}>{t("back")}</Button>
        <Button onClick={handleSign} disabled={!canSign} className="flex-1">
          {loading ? t("signing") : t("signButton")}
        </Button>
      </div>
    </div>
  );
};

export default SigningStep;
