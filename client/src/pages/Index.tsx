import { useNavigate } from "react-router-dom";
import { useI18n } from "@/contexts/I18nContext";
import { Button } from "@/components/ui/button";
import { Wallet, FileSignature } from "lucide-react";

const Index = () => {
  const { t } = useI18n();
  const navigate = useNavigate();

  return (
    <div className="py-12">
      <h1 className="mb-2 text-center text-3xl font-bold text-foreground">{t("hubTitle")}</h1>
      <p className="mb-12 text-center text-muted-foreground">{t("hubSubtitle")}</p>

      <div className="grid gap-6 sm:grid-cols-2">
        <button
          onClick={() => navigate("/create-wallet")}
          className="group rounded-xl border border-border bg-card p-8 text-left transition-all hover:border-primary/40 hover:shadow-md"
        >
          <Wallet className="mb-4 h-8 w-8 text-primary" />
          <h2 className="mb-2 text-xl font-semibold text-foreground">{t("createWallet")}</h2>
          <p className="text-sm text-muted-foreground">{t("hubCreateDesc")}</p>
        </button>

        <button
          onClick={() => navigate("/sign-transaction")}
          className="group rounded-xl border border-border bg-card p-8 text-left transition-all hover:border-primary/40 hover:shadow-md"
        >
          <FileSignature className="mb-4 h-8 w-8 text-primary" />
          <h2 className="mb-2 text-xl font-semibold text-foreground">{t("signTransaction")}</h2>
          <p className="text-sm text-muted-foreground">{t("hubSignDesc")}</p>
        </button>
      </div>
    </div>
  );
};

export default Index;
