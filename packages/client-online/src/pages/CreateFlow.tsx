import React, { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useI18n } from "@/lib/i18n";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input, Label } from "@/components/ui/Input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/RadioGroup";
import { Checkbox } from "@/components/ui/Checkbox";
import { Alert, AlertDescription } from "@/components/ui/Alert";
import { Separator } from "@/components/ui/Separator";
import { AddressDisplay } from "@/components/AddressDisplay";
import {
  isValidTronAddress,
  createUnsignedTransaction,
  createUnsignedTrc20Transfer,
  type UnsignedTransaction,
} from "@/lib/onlineCore";
import { resolveFullHost, isValidHttpUrl, USDT_CONTRACT, USDT_DECIMALS, type NetworkPreset } from "@/lib/network";

type Asset = "trx" | "usdt" | "custom";
type Phase = "form" | "review" | "done";

function convertTokenToSmallest(amount: string, decimals: number): string {
  const parts = amount.split(".");
  const whole = parts[0] || "0";
  const frac = (parts[1] || "").padEnd(decimals, "0").slice(0, decimals);
  const raw = whole + frac;
  return raw.replace(/^0+/, "") || "0";
}

type TrxAmountParse =
  | { ok: true; amountSun: number }
  | { ok: false; reason: "INVALID_FORMAT" | "NON_POSITIVE" | "TOO_LARGE" };

/**
 * Strictly converts TRX decimal string to integer SUN.
 * - up to 6 decimals
 * - rejects negatives / scientific notation / more than 6 decimals
 * - ensures it fits into JS safe integer range
 */
function parseTrxDecimalToSun(amountTrx: string): TrxAmountParse {
  const t = amountTrx.trim();
  if (!/^\d+(\.\d{1,6})?$/.test(t)) return { ok: false, reason: "INVALID_FORMAT" };

  const [whole, frac = ""] = t.split(".");
  const fracPadded = frac.padEnd(6, "0");
  const sunStr = `${whole}${fracPadded}`;
  let sun: bigint;
  try {
    sun = BigInt(sunStr);
  } catch {
    return { ok: false, reason: "INVALID_FORMAT" };
  }

  if (sun <= 0n) return { ok: false, reason: "NON_POSITIVE" };

  const maxSun = BigInt(Number.MAX_SAFE_INTEGER);
  if (sun > maxSun) return { ok: false, reason: "TOO_LARGE" };

  return { ok: true, amountSun: Number(sun) };
}

export default function CreateFlow() {
  const { t } = useI18n();
  const nav = useNavigate();

  const [phase, setPhase] = useState<Phase>("form");

  // form state
  const [network, setNetwork] = useState<NetworkPreset>("mainnet");
  const [hostOverride, setHostOverride] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [asset, setAsset] = useState<Asset>("usdt");
  const [amountStr, setAmountStr] = useState("");
  const [contractAddr, setContractAddr] = useState(USDT_CONTRACT);
  const [decimals, setDecimals] = useState(USDT_DECIMALS);

  // review state
  const [checks, setChecks] = useState([false, false, false]);
  const [building, setBuilding] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  // done state
  const [result, setResult] = useState<UnsignedTransaction | null>(null);

  const fullHost = resolveFullHost(network, hostOverride);

  // validation
  const errors = useMemo(() => {
    const e: string[] = [];
    if (from && !isValidTronAddress(from)) e.push(t("invalidAddress") + " (From)");
    if (to && !isValidTronAddress(to)) e.push(t("invalidAddress") + " (To)");
    if (from && to && from === to) e.push(t("addressesMustDiffer"));
    if (hostOverride && !isValidHttpUrl(hostOverride)) e.push(t("invalidUrl"));
    if (amountStr) {
      if (asset === "trx") {
        const parsed = parseTrxDecimalToSun(amountStr);
        if (!parsed.ok) {
          e.push(
            parsed.reason === "TOO_LARGE" ? t("amountTooLarge") : t("amountMustBePositive"),
          );
        }
      } else {
        const amt = parseFloat(amountStr);
        if (isNaN(amt) || amt <= 0) e.push(t("amountMustBePositive"));
      }
    }
    if (asset === "custom") {
      if (contractAddr && !isValidTronAddress(contractAddr)) e.push(t("invalidAddress") + " (Contract)");
      if (decimals < 0 || decimals > 18) e.push(t("invalidDecimals"));
    }
    return e;
  }, [from, to, amountStr, asset, contractAddr, decimals, hostOverride, t]);

  const trxAmountSun = useMemo<number | null>(() => {
    if (asset !== "trx") return null;
    if (!amountStr) return null;
    const parsed = parseTrxDecimalToSun(amountStr);
    return parsed.ok ? parsed.amountSun : null;
  }, [asset, amountStr]);

  const suspicious = to.length > 0 && isValidTronAddress(to) && (to.length < 34 || to.length > 36);

  const canProceed = Boolean(
    from &&
      to &&
      amountStr &&
      errors.length === 0 &&
      isValidTronAddress(from) &&
      isValidTronAddress(to) &&
      from !== to &&
      (asset === "trx"
        ? trxAmountSun !== null
        : parseFloat(amountStr) > 0) &&
      (asset !== "custom" || (isValidTronAddress(contractAddr) && decimals >= 0 && decimals <= 18)),
  );

  const handleExport = async () => {
    setBuilding(true);
    setExportError(null);
    try {
      let tx: UnsignedTransaction;
      if (asset === "trx") {
        const parsed = parseTrxDecimalToSun(amountStr);
        if (!parsed.ok) {
          throw new Error(
            parsed.reason === "TOO_LARGE" ? t("amountTooLarge") : t("amountMustBePositive"),
          );
        }
        tx = await createUnsignedTransaction({
          from,
          to,
          amountSun: parsed.amountSun,
          fullHost,
        });
      } else {
        const ca = asset === "usdt" ? USDT_CONTRACT : contractAddr;
        const dec = asset === "usdt" ? USDT_DECIMALS : decimals;
        tx = await createUnsignedTrc20Transfer({
          from, to, contractAddress: ca,
          amountSmallestUnit: convertTokenToSmallest(amountStr, dec),
          fullHost,
        });
      }
      // download
      const blob = new Blob([JSON.stringify(tx, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `unsigned-tron-${tx.txID.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(url);

      setResult(tx);
      setPhase("done");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setExportError(msg);
      return;
    } finally {
      setBuilding(false);
    }
  };

  const stepNum = phase === "form" ? 1 : phase === "review" ? 2 : 3;

  const assetLabel = asset === "trx" ? t("assetTrx") : asset === "usdt" ? t("assetUsdt") : t("assetCustom");

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">{t("stepOf", { current: stepNum, total: 3 })}</p>

      {phase === "form" && (
        <Card>
          <CardHeader><CardTitle>{t("createCardTitle")}</CardTitle></CardHeader>
          <CardContent className="space-y-5">
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
            </div>

            <Separator />

            {/* Addresses */}
            <div className="space-y-1">
              <Label>{t("fromAddress")}</Label>
              <Input value={from} onChange={(e) => setFrom(e.target.value.trim())} placeholder="T..." />
            </div>
            <div className="space-y-1">
              <Label>{t("toAddress")}</Label>
              <Input value={to} onChange={(e) => setTo(e.target.value.trim())} placeholder="T..." />
            </div>

            {suspicious && (
              <Alert variant="warning">
                <AlertDescription>{t("suspiciousAddress")}</AlertDescription>
              </Alert>
            )}

            <Separator />

            {/* Asset */}
            <div className="space-y-2">
              <Label>{t("assetType")}</Label>
              <RadioGroup value={asset} onValueChange={(v) => {
                const a = v as Asset;
                setAsset(a);
                if (a === "usdt") { setContractAddr(USDT_CONTRACT); setDecimals(USDT_DECIMALS); }
                if (a === "trx") { setContractAddr(""); setDecimals(6); }
                if (a === "custom") { setContractAddr(""); setDecimals(6); }
              }}>
                <RadioGroupItem value="trx">{t("assetTrx")}</RadioGroupItem>
                <RadioGroupItem value="usdt">{t("assetUsdt")}</RadioGroupItem>
                <RadioGroupItem value="custom">{t("assetCustom")}</RadioGroupItem>
              </RadioGroup>
            </div>

            {/* Asset-specific */}
            {asset === "trx" && (
              <div className="space-y-1">
                <Label>{t("amountTrx")}</Label>
                <Input type="number" step="0.000001" min="0" value={amountStr} onChange={(e) => setAmountStr(e.target.value)} />
              </div>
            )}

            {asset === "usdt" && (
              <div className="space-y-3">
                <div className="space-y-1">
                  <Label>{t("contractAddress")}</Label>
                  <Input value={USDT_CONTRACT} disabled />
                </div>
                <div className="space-y-1">
                  <Label>{t("decimalsLocked")}</Label>
                  <Input value="6" disabled />
                </div>
                <div className="space-y-1">
                  <Label>{t("amountToken")}</Label>
                  <Input type="number" step="any" min="0" value={amountStr} onChange={(e) => setAmountStr(e.target.value)} />
                </div>
              </div>
            )}

            {asset === "custom" && (
              <div className="space-y-3">
                <div className="space-y-1">
                  <Label>{t("contractAddress")}</Label>
                  <Input value={contractAddr} onChange={(e) => setContractAddr(e.target.value.trim())} placeholder="T..." />
                </div>
                <div className="space-y-1">
                  <Label>{t("decimals")}</Label>
                  <Input type="number" min="0" max="18" value={decimals} onChange={(e) => setDecimals(parseInt(e.target.value) || 0)} />
                </div>
                <div className="space-y-1">
                  <Label>{t("amountToken")}</Label>
                  <Input type="number" step="any" min="0" value={amountStr} onChange={(e) => setAmountStr(e.target.value)} />
                </div>
              </div>
            )}

            {/* Errors */}
            {errors.length > 0 && (
              <Alert variant="destructive">
                <AlertDescription>
                  <ul className="list-disc pl-4 space-y-0.5">
                    {errors.map((e, i) => <li key={i}>{e}</li>)}
                  </ul>
                </AlertDescription>
              </Alert>
            )}

            <Button disabled={!canProceed} onClick={() => { setChecks([false, false, false]); setPhase("review"); }} className="w-full">
              {t("nextReview")}
            </Button>
          </CardContent>
        </Card>
      )}

      {phase === "review" && (
        <Card>
          <CardHeader><CardTitle>{t("reviewTitle")}</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2 rounded-md border p-4 text-sm">
              <Row label={t("reviewNetwork")} value={`${network} — ${fullHost}`} />
              <Row label={t("reviewAsset")} value={assetLabel} />
              <Row label={t("reviewFrom")}><AddressDisplay address={from} /></Row>
              <Row label={t("reviewTo")}><AddressDisplay address={to} /></Row>
              {asset === "trx" && (
                <>
                  <Row label={t("reviewAmountTrx")} value={`${amountStr} TRX`} />
                  <Row
                    label={t("reviewAmountSun")}
                    value={trxAmountSun != null ? `${trxAmountSun} SUN` : "—"}
                    mono
                  />
                </>
              )}
              {asset !== "trx" && (
                <>
                  <Row label={t("reviewAmountToken")} value={amountStr} />
                  <Row label={t("reviewSmallestUnit")} value={convertTokenToSmallest(amountStr, asset === "usdt" ? USDT_DECIMALS : decimals)} mono />
                  <Row label={t("reviewContract")}><AddressDisplay address={asset === "usdt" ? USDT_CONTRACT : contractAddr} /></Row>
                  <Row label={t("reviewDecimals")} value={String(asset === "usdt" ? USDT_DECIMALS : decimals)} />
                </>
              )}
            </div>

            <Separator />

            <div className="space-y-3">
              {[t("checkVerifyAddresses"), t("checkUnderstandFunds"), t("checkCompareOffline")].map((txt, i) => (
                <label key={i} className="flex items-start gap-3 cursor-pointer">
                  <Checkbox checked={checks[i]} onChange={(v) => { const c = [...checks]; c[i] = v; setChecks(c); }} />
                  <span className="text-sm">{txt}</span>
                </label>
              ))}
            </div>

            <p className="text-xs text-muted-foreground italic">{t("protoDisclaimer")}</p>

            {exportError && (
              <Alert variant="destructive">
                <AlertDescription>{exportError}</AlertDescription>
              </Alert>
            )}

            <div className="flex gap-3">
              <Button
                variant="outline"
                onClick={() => {
                  setPhase("form");
                  setExportError(null);
                }}
              >
                {t("backToForm")}
              </Button>
              <Button
                disabled={!checks.every(Boolean) || building}
                onClick={handleExport}
                className="flex-1"
              >
                {building ? t("building") : t("exportButton")}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {phase === "done" && result && (
        <Card>
          <CardHeader><CardTitle>{t("doneTitle")}</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2 rounded-md border p-4 text-sm">
              <Row label={t("doneTxId")}><span className="font-mono text-xs break-all">{result.txID}</span></Row>
              <Row label={t("doneNetwork")} value={fullHost} />
            </div>
            <div className="flex gap-3">
              <Button
                variant="outline"
                onClick={() => {
                  setPhase("form");
                  setResult(null);
                  setChecks([false,false,false]);
                  setExportError(null);
                }}
              >
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

function Row({ label, value, mono, children }: { label: string; value?: string; mono?: boolean; children?: React.ReactNode }) {
  return (
    <div className="flex flex-col sm:flex-row sm:justify-between gap-0.5">
      <span className="font-medium text-muted-foreground">{label}</span>
      {children ?? <span className={mono ? "font-mono text-xs" : ""}>{value}</span>}
    </div>
  );
}
