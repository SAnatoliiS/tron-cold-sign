import React, { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useI18n } from "@/lib/i18n";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input, Label } from "@/components/ui/Input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/RadioGroup";
import { Checkbox } from "@/components/ui/Checkbox";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/Alert";
import { Separator } from "@/components/ui/Separator";
import { AddressDisplay } from "@/components/AddressDisplay";
import { buildUiSummaryFromRawData } from "@tron-cold-sign/core";
import { broadcastSignedTransaction, type SignedTransaction } from "@/lib/onlineCore";
import { resolveFullHost, isValidHttpUrl, type NetworkPreset } from "@/lib/network";
import type { TranslationKey } from "@/lib/i18n";

type Phase = "pick" | "preview" | "result";

export default function BroadcastFlow() {
  const { t } = useI18n();
  const nav = useNavigate();
  const fileRef = useRef<HTMLInputElement>(null);

  const [phase, setPhase] = useState<Phase>("pick");
  const [signedTx, setSignedTx] = useState<SignedTransaction | null>(null);
  const [fileError, setFileError] = useState("");

  // preview
  const [network, setNetwork] = useState<NetworkPreset>("mainnet");
  const [hostOverride, setHostOverride] = useState("");
  const [verified, setVerified] = useState(false);

  // result
  const [sending, setSending] = useState(false);
  const [success, setSuccess] = useState<{ txid: string } | null>(null);
  const [broadcastError, setBroadcastError] = useState<string | null>(null);

  const fullHost = resolveFullHost(network, hostOverride);
  const stepNum = phase === "pick" ? 1 : phase === "preview" ? 2 : 3;

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFileError("");
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const obj = JSON.parse(reader.result as string);
        // validate shape
        const checks: [boolean, TranslationKey][] = [
          [!obj.txID || typeof obj.txID !== "string", "fileMissingTxId"],
          [!obj.raw_data || typeof obj.raw_data !== "object" || Array.isArray(obj.raw_data), "fileMissingRawData"],
          [!obj.raw_data_hex || typeof obj.raw_data_hex !== "string", "fileMissingRawHex"],
          [!Array.isArray(obj.signature) || obj.signature.length === 0, "fileMissingSignature"],
        ];
        for (const [fail, key] of checks) {
          if (fail) { setFileError(t(key)); return; }
        }
        if (
          obj.signature.some(
            (s: unknown) => typeof s !== "string" || (typeof s === "string" && s.length === 0),
          )
        ) {
          setFileError(t("fileInvalidSignatureItem"));
          return;
        }
        setSignedTx(obj as SignedTransaction);
        setPhase("preview");
      } catch {
        setFileError(t("fileInvalidJson"));
      }
    };
    reader.readAsText(file);
  };

  const handleSend = async () => {
    if (!signedTx) return;
    setSending(true);
    setBroadcastError(null);
    try {
      const res = await broadcastSignedTransaction({ signedTx, fullHost });
      if (res.result) {
        setSuccess({ txid: res.txid ?? signedTx.txID });
      } else {
        setBroadcastError(res.message ?? "Unknown error");
      }
      setPhase("result");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setBroadcastError(msg);
      setPhase("result");
    } finally {
      setSending(false);
    }
  };

  let summaryBlock: ReturnType<typeof buildUiSummaryFromRawData> | null = null;
  let decodeError = "";
  if (signedTx) {
    try {
      summaryBlock = buildUiSummaryFromRawData(
        signedTx.raw_data as Record<string, unknown>,
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      decodeError = msg;
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">{t("stepOf", { current: stepNum, total: 3 })}</p>

      {phase === "pick" && (
        <Card>
          <CardHeader>
            <CardTitle>{t("pickFileTitle")}</CardTitle>
            <CardDescription>{t("pickFileDesc")}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <input ref={fileRef} type="file" accept=".json" className="hidden" onChange={handleFile} />
            <Button onClick={() => fileRef.current?.click()}>{t("pickFileButton")}</Button>
            {fileError && (
              <Alert variant="destructive">
                <AlertDescription>{fileError}</AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>
      )}

      {phase === "preview" && signedTx && (
        <Card>
          <CardHeader><CardTitle>{t("previewTitle")}</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2 rounded-md border p-4 text-sm">
              <Row label={t("previewTxId")}><span className="font-mono text-xs break-all">{signedTx.txID}</span></Row>

              {decodeError ? (
                <Alert variant="destructive" className="mt-2">
                  <AlertTitle>{t("previewDecodeFailed")}</AlertTitle>
                  <AlertDescription>{decodeError}</AlertDescription>
                </Alert>
              ) : summaryBlock && (
                <>
                  <Row label={t("previewType")} value={summaryBlock.summary.typeLabel} />
                  <Row label={t("previewFrom")}><AddressDisplay address={summaryBlock.summary.from} /></Row>
                  <Row label={t("previewTo")}><AddressDisplay address={summaryBlock.summary.to} /></Row>
                  <Row label={t("previewAmount")} value={summaryBlock.summary.amountText} />
                  {summaryBlock.summary.feeLimitText && <Row label={t("previewFeeLimit")} value={summaryBlock.summary.feeLimitText} />}
                  {summaryBlock.summary.tokenContract && (
                    <Row label={t("previewContract")}><AddressDisplay address={summaryBlock.summary.tokenContract} /></Row>
                  )}
                </>
              )}

              {summaryBlock && summaryBlock.warnings.length > 0 && (
                <div className="mt-2">
                  <p className="font-medium text-warning-foreground">{t("previewWarnings")}:</p>
                  <ul className="list-disc pl-4 text-xs text-muted-foreground">
                    {summaryBlock.warnings.map((w, i) => <li key={i}>{w}</li>)}
                  </ul>
                </div>
              )}
            </div>

            <Separator />

            {/* Network */}
            <div className="space-y-2">
              <Label>{t("networkLabel")}</Label>
              <RadioGroup value={network} onValueChange={(v) => setNetwork(v as NetworkPreset)}>
                <RadioGroupItem value="mainnet">{t("mainnet")}</RadioGroupItem>
                <RadioGroupItem value="shasta">{t("shasta")}</RadioGroupItem>
              </RadioGroup>
            </div>
            <div className="space-y-1">
              <Label>{t("fullHostOverride")}</Label>
              <Input value={hostOverride} onChange={(e) => setHostOverride(e.target.value)} placeholder={t("fullHostPlaceholder")} />
              {hostOverride && !isValidHttpUrl(hostOverride) && (
                <p className="text-xs text-destructive">{t("invalidUrl")}</p>
              )}
            </div>

            <Separator />

            <label className="flex items-start gap-3 cursor-pointer">
              <Checkbox checked={verified} onChange={setVerified} />
              <span className="text-sm">{t("verifyCheckbox")}</span>
            </label>
            <p className="text-xs text-destructive font-medium">{t("irreversibleWarning")}</p>

            <div className="flex gap-3">
              <Button variant="outline" onClick={() => { setPhase("pick"); setSignedTx(null); setVerified(false); }}>
                {t("backToForm")}
              </Button>
              <Button
                disabled={!verified || sending || (hostOverride.length > 0 && !isValidHttpUrl(hostOverride))}
                onClick={handleSend}
                className="flex-1"
              >
                {sending ? t("sending") : t("sendButton")}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {phase === "result" && (
        <Card>
          <CardContent className="space-y-4 pt-6">
            {success ? (
              <>
                <h3 className="text-xl font-semibold text-primary">{t("resultSuccessTitle")}</h3>
                <div className="rounded-md border p-4 text-sm">
                  <Row label={t("resultSuccessTxId")}><span className="font-mono text-xs break-all">{success.txid}</span></Row>
                </div>
              </>
            ) : (
              <>
                <h3 className="text-xl font-semibold text-destructive">{t("resultFailTitle")}</h3>
                {broadcastError && (
                  <details className="rounded-md border p-3 text-sm">
                    <summary className="cursor-pointer font-medium">{t("technicalDetails")}</summary>
                    <pre className="mt-2 whitespace-pre-wrap text-xs text-muted-foreground">{broadcastError}</pre>
                  </details>
                )}
              </>
            )}
            <div className="flex gap-3">
              <Button variant="outline" onClick={() => { setPhase("pick"); setSignedTx(null); setVerified(false); setSuccess(null); setBroadcastError(null); }}>
                {t("backToForm")}
              </Button>
              <Button variant="secondary" onClick={() => nav("/")}>{t("goHome")}</Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function Row({ label, value, children }: { label: string; value?: string; children?: React.ReactNode }) {
  return (
    <div className="flex flex-col sm:flex-row sm:justify-between gap-0.5">
      <span className="font-medium text-muted-foreground">{label}</span>
      {children ?? <span>{value}</span>}
    </div>
  );
}
