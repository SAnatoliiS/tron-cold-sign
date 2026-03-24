import { useState, useEffect, useRef } from "react";
import { useI18n } from "@/contexts/I18nContext";
import { Button } from "@/components/ui/button";
import CheckboxGate from "@/components/shared/CheckboxGate";
import StatusChip from "@/components/shared/StatusChip";
import { AlertTriangle } from "lucide-react";

interface PreScreenProps {
  onContinue: () => void;
}

const PreScreen = ({ onContinue }: PreScreenProps) => {
  const { t } = useI18n();
  const [checks, setChecks] = useState([false, false, false]);
  const allChecked = checks.every(Boolean);
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const toggle = (i: number) => (v: boolean) =>
    setChecks((prev) => prev.map((c, j) => (j === i ? v : c)));

  return (
    <div>
      <h2 ref={headingRef} tabIndex={-1} className="mb-4 text-2xl font-bold text-foreground outline-none">
        {t("preScreenTitle")}
      </h2>

      <div className="mb-4 flex flex-wrap gap-2">
        <StatusChip label={t("statusOffline")} />
        <StatusChip label={t("statusAirGapped")} />
        <StatusChip label={t("statusStaticBuild")} />
      </div>

      <div className="mb-6 rounded-lg border border-warning bg-warning/10 p-4">
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-warning-foreground">
          <AlertTriangle className="h-4 w-4 text-warning" />
          {t("preScreenWarning")}
        </div>
        <p className="text-sm text-muted-foreground">{t("preScreenNoPhotos")}</p>
        <p className="text-sm text-muted-foreground">{t("preScreenNoCloud")}</p>
      </div>

      <div className="mb-6 space-y-1">
        <CheckboxGate id="pre-1" label={t("preScreenCheck1")} checked={checks[0]} onChange={toggle(0)} />
        <CheckboxGate id="pre-2" label={t("preScreenCheck2")} checked={checks[1]} onChange={toggle(1)} />
        <CheckboxGate id="pre-3" label={t("preScreenCheck3")} checked={checks[2]} onChange={toggle(2)} />
      </div>

      <Button onClick={onContinue} disabled={!allChecked} className="w-full">
        {t("continue")}
      </Button>
    </div>
  );
};

export default PreScreen;
