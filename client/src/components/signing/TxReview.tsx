import { useState, useEffect, useRef } from "react";
import { useI18n } from "@/contexts/I18nContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import CheckboxGate from "@/components/shared/CheckboxGate";
import type { ParseUnsignedResult } from "@/lib/offlineApi";
import { AlertTriangle } from "lucide-react";

interface TxReviewProps {
  parsed: ParseUnsignedResult;
  onContinue: () => void;
  onBack: () => void;
}

const TxReview = ({ parsed, onContinue, onBack }: TxReviewProps) => {
  const { t } = useI18n();
  const [checks, setChecks] = useState([false, false, false]);
  const [last4, setLast4] = useState("");
  const [showHex, setShowHex] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const toggle = (i: number) => (v: boolean) =>
    setChecks((prev) => prev.map((c, j) => (j === i ? v : c)));

  const expectedLast4 = parsed.summary.to.slice(-4);
  const last4Valid = last4.length === 4 && last4 === expectedLast4;
  const allGatesPassed = checks.every(Boolean) && last4Valid;

  const summaryRows = [
    { label: t("txType"), value: parsed.summary.typeLabel },
    { label: t("txFrom"), value: parsed.summary.from },
    { label: t("txTo"), value: parsed.summary.to },
    ...(parsed.summary.tokenContract
      ? [{ label: t("txToken"), value: `${parsed.summary.tokenLabel ?? ""} (${parsed.summary.tokenContract})` }]
      : []),
    { label: t("txAmount"), value: parsed.summary.amountText },
    { label: t("txFeeLimit"), value: parsed.summary.feeLimitText },
  ];

  return (
    <div>
      <h2 ref={headingRef} tabIndex={-1} className="mb-6 text-2xl font-bold text-foreground outline-none">
        {t("reviewTitle")}
      </h2>

      {/* Human-readable summary */}
      <div className="mb-6 space-y-2 rounded-lg border border-border bg-muted/50 p-4 text-sm">
        {summaryRows.map((r) => (
          <div key={r.label} className="flex justify-between gap-4">
            <span className="shrink-0 text-muted-foreground">{r.label}</span>
            <span className="break-all text-right font-medium text-foreground">{r.value}</span>
          </div>
        ))}
      </div>

      {/* Warnings */}
      {parsed.warnings.length > 0 && (
        <div className="mb-4 rounded-lg border border-warning bg-warning/10 p-3">
          <p className="mb-1 text-sm font-semibold text-warning-foreground">{t("warnings")}</p>
          <ul className="list-inside list-disc text-sm text-muted-foreground">
            {parsed.warnings.map((w, i) => <li key={i}>{w}</li>)}
          </ul>
        </div>
      )}

      {/* Anti-substitution block */}
      <div className="mb-6 rounded-lg border border-destructive/30 bg-destructive/5 p-4">
        <div className="mb-2 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-destructive" />
          <h3 className="text-sm font-semibold text-foreground">{t("antiSubstitutionTitle")}</h3>
        </div>
        <p className="mb-3 text-xs text-muted-foreground">{t("antiSubstitutionWarning")}</p>

        <div className="mb-2 text-sm">
          <span className="text-muted-foreground">{t("txId")}: </span>
          <span className="break-all font-mono text-xs text-foreground">{parsed.txId}</span>
        </div>

        <button
          onClick={() => setShowHex(!showHex)}
          className="mb-1 text-xs text-primary hover:underline"
        >
          {showHex ? t("hideRawHex") : t("showRawHex")}
        </button>

        {showHex && (
          <div className="mt-1 max-h-32 overflow-auto rounded border border-border bg-muted p-2">
            <pre className="whitespace-pre-wrap break-all font-mono text-xs text-foreground">
              {parsed.rawDataHex}
            </pre>
          </div>
        )}
      </div>

      {/* Gate checkboxes */}
      <div className="mb-4 space-y-1">
        <CheckboxGate id="rev-1" label={t("reviewCheck1")} checked={checks[0]} onChange={toggle(0)} />
        <CheckboxGate id="rev-2" label={t("reviewCheck2")} checked={checks[1]} onChange={toggle(1)} />
        <CheckboxGate id="rev-3" label={t("reviewCheck3")} checked={checks[2]} onChange={toggle(2)} />
      </div>

      {/* Last-4 challenge */}
      <div className="mb-6">
        <label htmlFor="last4" className="mb-1 block text-sm font-medium text-foreground">
          {t("last4Challenge")}
        </label>
        <Input
          id="last4"
          autoComplete="off"
          maxLength={4}
          value={last4}
          onChange={(e) => setLast4(e.target.value)}
          className="max-w-[8rem] font-mono"
        />
        {last4.length === 4 && !last4Valid && (
          <p className="mt-1 text-sm text-destructive" role="alert" aria-live="assertive">
            {t("last4Incorrect")}
          </p>
        )}
      </div>

      <div className="flex gap-3">
        <Button variant="outline" onClick={onBack}>{t("back")}</Button>
        <Button onClick={onContinue} disabled={!allGatesPassed} className="flex-1">
          {t("continueToSigning")}
        </Button>
      </div>
    </div>
  );
};

export default TxReview;
