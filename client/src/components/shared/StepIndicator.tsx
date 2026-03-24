import { useI18n } from "@/contexts/I18nContext";

interface StepIndicatorProps {
  current: number;
  total: number;
}

const StepIndicator = ({ current, total }: StepIndicatorProps) => {
  const { t } = useI18n();

  return (
    <div className="mb-6">
      <p className="text-sm font-medium text-muted-foreground">
        {t("stepOf", { current, total })}
      </p>
      <div className="mt-2 flex gap-1.5">
        {Array.from({ length: total }, (_, i) => (
          <div
            key={i}
            className={`h-1.5 flex-1 rounded-full transition-colors ${
              i < current ? "bg-primary" : "bg-border"
            }`}
          />
        ))}
      </div>
    </div>
  );
};

export default StepIndicator;
