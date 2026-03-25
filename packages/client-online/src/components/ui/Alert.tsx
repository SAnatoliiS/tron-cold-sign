import React from "react";

const variantStyles: Record<string, string> = {
  default: "border bg-background text-foreground",
  destructive: "border-destructive/50 bg-destructive/10 text-destructive",
  warning: "border-warning/50 bg-warning/10 text-warning-foreground",
};

interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "destructive" | "warning";
}

export function Alert({ variant = "default", className = "", ...props }: AlertProps) {
  return <div role="alert" className={`relative w-full rounded-lg border p-4 ${variantStyles[variant]} ${className}`} {...props} />;
}

export function AlertTitle({ className = "", ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h5 className={`mb-1 font-semibold leading-none tracking-tight ${className}`} {...props} />;
}

export function AlertDescription({ className = "", ...props }: React.HTMLAttributes<HTMLParagraphElement>) {
  return <div className={`text-sm [&_p]:leading-relaxed ${className}`} {...props} />;
}
