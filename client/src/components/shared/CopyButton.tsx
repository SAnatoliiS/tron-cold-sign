import { useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Copy, Check } from "lucide-react";
import ConfirmModal from "./ConfirmModal";
import { useI18n } from "@/contexts/I18nContext";

interface CopyButtonProps {
  text: string;
  label: string;
  variant?: "default" | "outline" | "secondary" | "ghost";
}

const CopyButton = ({ text, label, variant = "outline" }: CopyButtonProps) => {
  const { t } = useI18n();
  const [showModal, setShowModal] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleConfirm = useCallback(async () => {
    setShowModal(false);
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard may not be available on file://
    }
  }, [text]);

  return (
    <>
      <Button variant={variant} size="sm" onClick={() => setShowModal(true)}>
        {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
        {copied ? t("copied") : label}
      </Button>
      <ConfirmModal
        open={showModal}
        onClose={() => setShowModal(false)}
        onConfirm={handleConfirm}
      />
    </>
  );
};

export default CopyButton;
