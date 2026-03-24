import { useState, useEffect, useRef } from "react";
import { useI18n } from "@/contexts/I18nContext";
import { Button } from "@/components/ui/button";
import CheckboxGate from "@/components/shared/CheckboxGate";

interface FinalConfirmProps {
  onFinish: () => void;
  onBack: () => void;
}

const FinalConfirm = ({ onFinish, onBack }: FinalConfirmProps) => {
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
      <h2 ref={headingRef} tabIndex={-1} className="mb-6 text-2xl font-bold text-foreground outline-none">
        {t("finalTitle")}
      </h2>

      <div className="mb-6 space-y-1">
        <CheckboxGate id="final-1" label={t("finalCheck1")} checked={checks[0]} onChange={toggle(0)} />
        <CheckboxGate id="final-2" label={t("finalCheck2")} checked={checks[1]} onChange={toggle(1)} />
        <CheckboxGate id="final-3" label={t("finalCheck3")} checked={checks[2]} onChange={toggle(2)} />
      </div>

      <div className="flex gap-3">
        <Button variant="outline" onClick={onBack}>{t("back")}</Button>
        <Button onClick={onFinish} disabled={!allChecked} className="flex-1">
          {t("finish")}
        </Button>
      </div>
    </div>
  );
};

export default FinalConfirm;
