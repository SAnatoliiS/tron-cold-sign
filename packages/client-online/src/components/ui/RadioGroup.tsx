import React, { createContext, useContext } from "react";

const Ctx = createContext<{ value: string; onChange: (v: string) => void }>({ value: "", onChange: () => {} });

interface RadioGroupProps {
  value: string;
  onValueChange: (v: string) => void;
  children: React.ReactNode;
  className?: string;
}

export function RadioGroup({ value, onValueChange, children, className = "" }: RadioGroupProps) {
  return (
    <Ctx.Provider value={{ value, onChange: onValueChange }}>
      <div role="radiogroup" className={`flex flex-wrap gap-3 ${className}`}>
        {children}
      </div>
    </Ctx.Provider>
  );
}

interface RadioGroupItemProps {
  value: string;
  id?: string;
  children: React.ReactNode;
}

export function RadioGroupItem({ value, id, children }: RadioGroupItemProps) {
  const ctx = useContext(Ctx);
  const selected = ctx.value === value;
  return (
    <label
      htmlFor={id}
      className={`inline-flex cursor-pointer items-center gap-2 rounded-md border px-3 py-2 text-sm transition-colors ${
        selected ? "border-primary bg-primary/10 text-foreground" : "border-input bg-background text-muted-foreground hover:bg-muted"
      }`}
    >
      <input
        type="radio"
        id={id}
        name="radio"
        className="sr-only"
        checked={selected}
        onChange={() => ctx.onChange(value)}
      />
      <span
        className={`inline-block h-3.5 w-3.5 rounded-full border-2 ${
          selected ? "border-primary bg-primary" : "border-muted-foreground"
        }`}
      />
      {children}
    </label>
  );
}
