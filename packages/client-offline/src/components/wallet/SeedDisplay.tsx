import { useState, useCallback, useEffect, useRef } from "react";
import { useI18n } from "@/contexts/I18nContext";
import { Button } from "@/components/ui/button";
import CountdownTimer from "@/components/shared/CountdownTimer";
import { Eye, EyeOff } from "lucide-react";

interface SeedDisplayProps {
  mnemonic: string;
  onContinue: () => void;
  onBack: () => void;
}

const SEED_TIMER_SECONDS = 120;

const SeedDisplay = ({ mnemonic, onContinue, onBack }: SeedDisplayProps) => {
  const { t } = useI18n();
  const words = mnemonic.split(" ");
  const [visible, setVisible] = useState(true);
  const [timerExpired, setTimerExpired] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const handleExpire = useCallback(() => {
    setVisible(false);
    setTimerExpired(true);
  }, []);

  return (
    <div>
      <h2 ref={headingRef} tabIndex={-1} className="mb-2 text-2xl font-bold text-foreground outline-none">
        {t("seedTitle")}
      </h2>
      <p className="mb-4 text-sm text-destructive font-medium">{t("seedWarning")}</p>

      <div className="mb-3 flex items-center justify-between">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setVisible(!visible)}
          aria-label={visible ? t("hideSeed") : t("showSeed")}
        >
          {visible ? <EyeOff className="mr-1.5 h-4 w-4" /> : <Eye className="mr-1.5 h-4 w-4" />}
          {visible ? t("hideSeed") : t("showSeed")}
        </Button>
        {!timerExpired && (
          <CountdownTimer
            seconds={SEED_TIMER_SECONDS}
            onExpire={handleExpire}
            label={(s) => t("seedAutoHide", { seconds: s })}
          />
        )}
      </div>

      {timerExpired && !visible && (
        <p className="mb-3 text-xs text-muted-foreground">{t("seedTimerExpired")}</p>
      )}

      <div
        className={`mb-6 grid grid-cols-3 gap-2 rounded-lg border border-border bg-muted/50 p-4 transition-all sm:grid-cols-4 ${
          !visible ? "select-none blur-md" : ""
        }`}
        aria-hidden={!visible}
      >
        {words.map((word, i) => (
          <div key={i} className="flex items-baseline gap-1.5 rounded-md bg-card px-2 py-1.5">
            <span className="text-xs text-muted-foreground">{i + 1}.</span>
            <span className="text-sm font-medium text-foreground">{word}</span>
          </div>
        ))}
      </div>

      <div className="flex gap-3">
        <Button variant="outline" onClick={onBack}>{t("back")}</Button>
        <Button onClick={onContinue} className="flex-1">{t("continue")}</Button>
      </div>
    </div>
  );
};

export default SeedDisplay;
