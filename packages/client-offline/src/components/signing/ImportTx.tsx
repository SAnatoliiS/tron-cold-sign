import { useState, useCallback, useRef, useEffect } from "react";
import { useI18n } from "@/contexts/I18nContext";
import { Button } from "@/components/ui/button";
import { hashFile } from "@/lib/offlineApi";
import { FileUp } from "lucide-react";

interface ImportTxProps {
  onFileLoaded: (file: File, text: string, sha256: string) => void;
}

const ImportTx = ({ onFileLoaded }: ImportTxProps) => {
  const { t } = useI18n();
  const inputRef = useRef<HTMLInputElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileSize, setFileSize] = useState(0);
  const [sha256, setSha256] = useState<string | null>(null);
  const [computing, setComputing] = useState(false);
  const [fileText, setFileText] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [loadedFile, setLoadedFile] = useState<File | null>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const processFile = useCallback(async (file: File) => {
    setFileName(file.name);
    setFileSize(file.size);
    setComputing(true);
    setSha256(null);

    const text = await file.text();
    setFileText(text);
    setLoadedFile(file);

    const hash = await hashFile(file);
    setSha256(hash);
    setComputing(false);
  }, []);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) processFile(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    const file = e.dataTransfer.files?.[0];
    if (file) processFile(file);
  };

  const handleNext = () => {
    if (loadedFile && fileText && sha256) {
      onFileLoaded(loadedFile, fileText, sha256);
    }
  };

  const ready = !!fileName && !!sha256 && !computing;

  return (
    <div>
      <h2 ref={headingRef} tabIndex={-1} className="mb-2 text-2xl font-bold text-foreground outline-none">
        {t("importTitle")}
      </h2>
      <p className="mb-6 text-sm text-muted-foreground">{t("importInstruction")}</p>

      <div
        className={`mb-6 flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed p-10 transition-colors ${
          dragActive ? "border-primary bg-primary/5" : "border-border"
        }`}
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
        onDragLeave={() => setDragActive(false)}
        onDrop={handleDrop}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => e.key === "Enter" && inputRef.current?.click()}
      >
        <FileUp className="mb-2 h-8 w-8 text-muted-foreground" />
        <p className="text-sm font-medium text-foreground">{t("dragDrop")}</p>
        <p className="text-xs text-muted-foreground">{t("orClickBrowse")}</p>
        <input
          ref={inputRef}
          type="file"
          accept=".json,.txt"
          className="hidden"
          onChange={handleInputChange}
        />
      </div>

      {fileName && (
        <div className="mb-6 space-y-2 rounded-lg border border-border bg-muted/50 p-4 text-sm">
          <div className="flex justify-between">
            <span className="text-muted-foreground">{t("fileName")}</span>
            <span className="font-medium text-foreground">{fileName}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">{t("fileSize")}</span>
            <span className="font-medium text-foreground">{fileSize} {t("bytes")}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">{t("fileSha256")}</span>
            <span className="break-all font-mono text-xs font-medium text-foreground">
              {computing ? t("computing") : sha256}
            </span>
          </div>
        </div>
      )}

      <Button onClick={handleNext} disabled={!ready} className="w-full">
        {t("next")}
      </Button>
    </div>
  );
};

export default ImportTx;
