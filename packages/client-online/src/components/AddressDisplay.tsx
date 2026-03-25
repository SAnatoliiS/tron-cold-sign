import React from "react";

export function AddressDisplay({ address }: { address: string }) {
  const chunks: string[] = [];
  for (let i = 0; i < address.length; i += 4) {
    chunks.push(address.slice(i, i + 4));
  }
  return (
    <span className="font-mono text-sm break-all">
      {chunks.map((c, i) => (
        <React.Fragment key={i}>
          {i > 0 && " "}
          {c}
        </React.Fragment>
      ))}
    </span>
  );
}
