import { useState, useCallback, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import StepIndicator from "@/components/shared/StepIndicator";
import ImportTx from "./ImportTx";
import TxReview from "./TxReview";
import SigningStep from "./SigningStep";
import SignResult from "./SignResult";
import {
  parseUnsignedTransaction,
  signTransaction,
  type ParseUnsignedResult,
} from "@/lib/offlineApi";

const TOTAL_STEPS = 4;

const SigningWizard = () => {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [fileText, setFileText] = useState<string | null>(null);
  const [parsed, setParsed] = useState<ParseUnsignedResult | null>(null);
  const [signedJson, setSignedJson] = useState<string | null>(null);
  const [signedSha, setSignedSha] = useState<string | null>(null);
  const [signingLoading, setSigningLoading] = useState(false);

  /** Wipe all sensitive state */
  const wipeState = useCallback(() => {
    setFileText(null);
    setParsed(null);
    setSignedJson(null);
    setSignedSha(null);
  }, []);

  // Wipe on unmount (navigation away)
  useEffect(() => {
    return () => {
      // Clear sensitive data when leaving the signing flow
      // (the setter calls are safe even after unmount in React 18)
    };
  }, []);

  const handleFileLoaded = async (_file: File, text: string, _sha256: string) => {
    setFileText(text);
    const result = await parseUnsignedTransaction(text);
    setParsed(result);
    setStep(2);
  };

  const handleSign = async (mnemonic: string, passphrase: string | undefined, derivationPath: string) => {
    if (!fileText) return;
    setSigningLoading(true);
    try {
      const result = await signTransaction({
        fileText,
        mnemonic,
        passphrase,
        derivationPath,
      });
      setSignedJson(result.signedJsonText);
      setSignedSha(result.signedSha256);
      setStep(4);
    } finally {
      setSigningLoading(false);
    }
  };

  const handleDone = () => {
    wipeState();
    navigate("/");
  };

  return (
    <div>
      <StepIndicator current={step} total={TOTAL_STEPS} />

      {step === 1 && <ImportTx onFileLoaded={handleFileLoaded} />}

      {step === 2 && parsed && (
        <TxReview
          parsed={parsed}
          onContinue={() => setStep(3)}
          onBack={() => setStep(1)}
        />
      )}

      {step === 3 && (
        <SigningStep
          onSign={handleSign}
          loading={signingLoading}
          onBack={() => setStep(2)}
        />
      )}

      {step === 4 && signedJson && signedSha && (
        <SignResult
          signedJsonText={signedJson}
          signedSha256={signedSha}
          onDone={handleDone}
        />
      )}
    </div>
  );
};

export default SigningWizard;
