import React from "react";

interface CheckboxProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  id?: string;
  disabled?: boolean;
}

export function Checkbox({ checked, onChange, id, disabled }: CheckboxProps) {
  return (
    <button
      id={id}
      role="checkbox"
      type="button"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-sm border border-primary transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
        checked ? "bg-primary text-primary-foreground" : "bg-background"
      } disabled:opacity-50`}
    >
      {checked && (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="20 6 9 17 4 12" />
        </svg>
      )}
    </button>
  );
}
