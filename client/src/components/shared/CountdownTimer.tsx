import { useState, useEffect, useRef } from "react";

interface CountdownTimerProps {
  seconds: number;
  onExpire: () => void;
  /** Label builder: receives remaining seconds */
  label: (remaining: number) => string;
}

const CountdownTimer = ({ seconds, onExpire, label }: CountdownTimerProps) => {
  const [remaining, setRemaining] = useState(seconds);
  const expiredRef = useRef(false);

  useEffect(() => {
    if (remaining <= 0 && !expiredRef.current) {
      expiredRef.current = true;
      onExpire();
      return;
    }
    const id = setInterval(() => setRemaining((r) => r - 1), 1000);
    return () => clearInterval(id);
  }, [remaining, onExpire]);

  if (remaining <= 0) return null;

  return (
    <span className="text-xs text-muted-foreground">{label(remaining)}</span>
  );
};

export default CountdownTimer;
