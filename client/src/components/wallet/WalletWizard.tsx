import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import StepIndicator from "@/components/shared/StepIndicator";
import PreScreen from "./PreScreen";
import GenerationSettings from "./GenerationSettings";
import SeedDisplay from "./SeedDisplay";
import SeedConfirm from "./SeedConfirm";
import AddressDisplay from "./AddressDisplay";
import FinalConfirm from "./FinalConfirm";
import { generateWallet, type GeneratedWallet } from "@/lib/offlineApi";
import { useI18n } from "@/contexts/I18nContext";
import { Button } from "@/components/ui/button";
import { CheckCircle2 } from "lucide-react";

const TOTAL_STEPS = 6;

const WalletWizard = () => {
  const { t } = useI18n();
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [wallet, setWallet] = useState<GeneratedWallet | null>(null);
  const [passphrase, setPassphrase] = useState<string | undefined>();
  const [done, setDone] = useState(false);

  /** Wipe all sensitive state */
  const wipeState = useCallback(() => {
    setWallet(null);
    setPassphrase(undefined);
  }, []);

  const handleGenerate = async (wordCount: 12 | 24, pp?: string) => {
    setLoading(true);
    try {
      const result = await generateWallet({ wordCount, passphrase: pp });
      setWallet(result);
      setPassphrase(pp);
      setStep(3);
    } finally {
      setLoading(false);
    }
  };

  const handleFinish = () => {
    wipeState();
    setDone(true);
  };

  const handleBack = (toStep: number) => () => setStep(toStep);

  // If navigating away, wipe
  const handleGoHome = () => {
    wipeState();
    navigate("/");
  };

  if (done) {
    return (
      <div className="py-12 text-center">
        <CheckCircle2 className="mx-auto mb-4 h-16 w-16 text-primary" />
        <h2 className="mb-2 text-2xl font-bold text-foreground">{t("walletCreated")}</h2>
        <Button onClick={handleGoHome} className="mt-6">{t("returnHome")}</Button>
      </div>
    );
  }

  return (
    <div>
      <StepIndicator current={step} total={TOTAL_STEPS} />

      {step === 1 && <PreScreen onContinue={() => setStep(2)} />}

      {step === 2 && (
        <GenerationSettings
          onGenerate={handleGenerate}
          loading={loading}
          onBack={handleBack(1)}
        />
      )}

      {step === 3 && wallet && (
        <SeedDisplay
          mnemonic={wallet.mnemonic}
          onContinue={() => setStep(4)}
          onBack={handleBack(2)}
        />
      )}

      {step === 4 && wallet && (
        <SeedConfirm
          mnemonic={wallet.mnemonic}
          onConfirmed={() => setStep(5)}
          onBack={handleBack(3)}
        />
      )}

      {step === 5 && wallet && (
        <AddressDisplay
          addressBase58={wallet.addressBase58}
          addressHex={wallet.addressHex}
          onContinue={() => setStep(6)}
          onBack={handleBack(4)}
        />
      )}

      {step === 6 && (
        <FinalConfirm onFinish={handleFinish} onBack={handleBack(5)} />
      )}
    </div>
  );
};

export default WalletWizard;
