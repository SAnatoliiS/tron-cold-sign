import { useState, useMemo, useEffect, useRef } from "react";
import { useI18n } from "@/contexts/I18nContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface SeedConfirmProps {
  mnemonic: string;
  onConfirmed: () => void;
  onBack: () => void;
}

/** Pick 3 random distinct indices from the mnemonic. Deterministic for the session via useMemo. */
function pickIndices(wordCount: number): number[] {
  const indices: number[] = [];
  const used = new Set<number>();
  // Simple seeded random isn't needed for a stub — just pick spread-out indices
  const step = Math.floor(wordCount / 4);
  for (let k = 0; k < 3; k++) {
    let idx = step * (k + 1) - 1;
    while (used.has(idx)) idx++;
    used.add(idx);
    indices.push(idx);
  }
  return indices;
}

const SeedConfirm = ({ mnemonic, onConfirmed, onBack }: SeedConfirmProps) => {
  const { t } = useI18n();
  const words = mnemonic.split(" ");
  const indices = useMemo(() => pickIndices(words.length), [words.length]);
  const [answers, setAnswers] = useState<string[]>(["", "", ""]);
  const [submitted, setSubmitted] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const correct = indices.map((idx, k) => answers[k].trim().toLowerCase() === words[idx].toLowerCase());
  const allCorrect = correct.every(Boolean);

  const handleChange = (k: number, v: string) => {
    setSubmitted(false);
    setAnswers((prev) => prev.map((a, j) => (j === k ? v : a)));
  };

  const handleSubmit = () => {
    setSubmitted(true);
    if (allCorrect) onConfirmed();
  };

  return (
    <div>
      <h2 ref={headingRef} tabIndex={-1} className="mb-2 text-2xl font-bold text-foreground outline-none">
        {t("confirmTitle")}
      </h2>
      <p className="mb-6 text-sm text-muted-foreground">{t("confirmInstruction")}</p>

      <div className="mb-6 space-y-4">
        {indices.map((idx, k) => (
          <div key={idx}>
            <label htmlFor={`word-${idx}`} className="mb-1 block text-sm font-medium text-foreground">
              {t("wordNumber", { n: idx + 1 })}
            </label>
            <Input
              id={`word-${idx}`}
              autoComplete="off"
              value={answers[k]}
              onChange={(e) => handleChange(k, e.target.value)}
              className={submitted && !correct[k] ? "border-destructive" : ""}
            />
            {submitted && !correct[k] && (
              <p className="mt-1 text-sm text-destructive" role="alert" aria-live="assertive">
                {t("wordIncorrect")}
              </p>
            )}
          </div>
        ))}
      </div>

      {submitted && allCorrect && (
        <p className="mb-4 text-sm font-medium text-primary" role="status" aria-live="assertive">
          {t("allCorrect")}
        </p>
      )}

      <div className="flex gap-3">
        <Button variant="outline" onClick={onBack}>{t("back")}</Button>
        <Button onClick={handleSubmit} className="flex-1">
          {t("continue")}
        </Button>
      </div>
    </div>
  );
};

export default SeedConfirm;
