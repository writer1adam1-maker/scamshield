"use client";

import { useEffect } from "react";
import { AlertTriangle, RotateCcw } from "lucide-react";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[ScamShield] Page error:", error);
  }, [error]);

  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-center px-4">
      <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl border border-danger/20 bg-danger/5 text-danger mb-6">
        <AlertTriangle size={32} />
      </div>
      <h2 className="text-xl font-semibold text-text-primary mb-2">
        Something went wrong
      </h2>
      <p className="text-sm text-text-secondary max-w-md mb-6">
        An error occurred while rendering this page. Click below to try again.
      </p>
      <button
        onClick={reset}
        className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-shield text-void font-semibold text-sm hover:bg-shield-dim transition-colors"
      >
        <RotateCcw size={16} />
        Try again
      </button>
    </div>
  );
}
