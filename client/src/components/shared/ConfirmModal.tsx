import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/contexts/I18nContext";

interface ConfirmModalProps {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
}

const ConfirmModal = ({ open, onClose, onConfirm }: ConfirmModalProps) => {
  const { t } = useI18n();

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("confirmCopyTitle")}</DialogTitle>
          <DialogDescription>{t("confirmCopyMessage")}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t("confirmCopyCancel")}
          </Button>
          <Button onClick={onConfirm}>{t("confirmCopyProceed")}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default ConfirmModal;
