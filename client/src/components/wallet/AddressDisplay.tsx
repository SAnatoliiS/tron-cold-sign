import { useState, useEffect, useRef } from "react";
import { useI18n } from "@/contexts/I18nContext";
import { Button } from "@/components/ui/button";
import CopyButton from "@/components/shared/CopyButton";

interface AddressDisplayProps {
  addressBase58: string;
  addressHex?: string;
  onContinue: () => void;
  onBack: () => void;
}

const AddressDisplay = ({ addressBase58, addressHex, onContinue, onBack }: AddressDisplayProps) => {
  const { t } = useI18n();
  const [showFull, setShowFull] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  // Break address into readable 4-char blocks
  const blocks = addressBase58.match(/.{1,4}/g) ?? [addressBase58];

  return (
    <div>
      <h2 ref={headingRef} tabIndex={-1} className="mb-6 text-2xl font-bold text-foreground outline-none">
        {t("addressTitle")}
      </h2>

      <div className="mb-4">
        <label className="mb-1 block text-sm font-medium text-muted-foreground">
          {t("addressBase58")}
        </label>
        <div className="rounded-lg border border-border bg-muted/50 p-4">
          <p className="font-mono text-base leading-relaxed text-foreground">
            {blocks.join(" ")}
          </p>
        </div>
      </div>

      {addressHex && (
        <div className="mb-4">
          <button
            onClick={() => setShowFull(!showFull)}
            className="text-sm text-primary hover:underline"
          >
            {showFull ? t("hideFullAddress") : t("showFullAddress")}
          </button>
          {showFull && (
            <div className="mt-2 rounded-lg border border-border bg-muted/50 p-4">
              <label className="mb-1 block text-xs text-muted-foreground">{t("addressHex")}</label>
              <p className="break-all font-mono text-xs text-foreground">{addressHex}</p>
            </div>
          )}
        </div>
      )}

      {/* TODO: Replace with bundled offline QR library (no CDN) */}
      <div className="mb-6 flex items-center justify-center rounded-lg border border-dashed border-border p-8">
        <p className="text-sm text-muted-foreground">{t("qrPlaceholder")}</p>
      </div>

      <div className="mb-4">
        <CopyButton text={addressBase58} label={t("copyAddress")} />
      </div>

      <div className="flex gap-3">
        <Button variant="outline" onClick={onBack}>{t("back")}</Button>
        <Button onClick={onContinue} className="flex-1">{t("continue")}</Button>
      </div>
    </div>
  );
};

export default AddressDisplay;
