interface StatusChipProps {
  label: string;
}

const StatusChip = ({ label }: StatusChipProps) => (
  <span className="inline-flex items-center rounded-full bg-secondary px-2.5 py-0.5 text-xs font-medium text-secondary-foreground">
    {label}
  </span>
);

export default StatusChip;
