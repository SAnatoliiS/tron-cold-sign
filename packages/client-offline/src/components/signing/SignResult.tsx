import { useEffect, useRef } from "react";
import { useI18n } from "@/contexts/I18nContext";
import { Button } from "@/components/ui/button";
import CopyButton from "@/components/shared/CopyButton";
import { Download, CheckCircle2 } from "lucide-react";

interface SignResultProps {
  signedJsonText: string;
  signedSha256: string;
  onDone: () => void;
}

const SignResult = ({ signedJsonText, signedSha256, onDone }: SignResultProps) => {
  const { t } = useI18n();
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const handleDownload = () => {
    const blob = new Blob([signedJsonText], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "signed_transaction.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <div className="mb-6 flex items-center gap-3">
        <CheckCircle2 className="h-8 w-8 text-primary" />
        <h2 ref={headingRef} tabIndex={-1} className="text-2xl font-bold text-foreground outline-none">
          {t("resultTitle")}
        </h2>
      </div>

      <div className="mb-6 space-y-2 rounded-lg border border-border bg-muted/50 p-4 text-sm">
        <div className="flex justify-between">
          <span className="text-muted-foreground">{t("signedSize")}</span>
          <span className="font-medium text-foreground">
            {new Blob([signedJsonText]).size} {t("bytes")}
          </span>
        </div>
        <div className="flex justify-between">
          <span className="text-muted-foreground">{t("signedSha256")}</span>
          <span className="break-all font-mono text-xs font-medium text-foreground">{signedSha256}</span>
        </div>
      </div>

      <div className="flex flex-wrap gap-3">
        <Button onClick={handleDownload}>
          <Download className="mr-1.5 h-4 w-4" />
          {t("downloadSigned")}
        </Button>
        <CopyButton text={signedJsonText} label={t("copySigned")} />
      </div>

      <div className="mt-8">
        <Button variant="outline" onClick={onDone}>{t("returnHome")}</Button>
      </div>
    </div>
  );
};

export default SignResult;
