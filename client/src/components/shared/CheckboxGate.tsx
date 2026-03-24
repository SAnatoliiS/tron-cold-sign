import { Checkbox } from "@/components/ui/checkbox";

interface CheckboxGateProps {
  id: string;
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}

const CheckboxGate = ({ id, label, checked, onChange }: CheckboxGateProps) => (
  <div className="flex items-start gap-3 py-1.5">
    <Checkbox
      id={id}
      checked={checked}
      onCheckedChange={(v) => onChange(v === true)}
      className="mt-0.5"
    />
    <label htmlFor={id} className="cursor-pointer text-sm leading-snug text-foreground">
      {label}
    </label>
  </div>
);

export default CheckboxGate;
