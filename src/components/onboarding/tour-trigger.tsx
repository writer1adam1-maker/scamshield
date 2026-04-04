"use client";

import { useEffect, useState } from "react";
import { HelpCircle } from "lucide-react";
import { usePathname } from "next/navigation";
import { useTour } from "./tour-provider";
import { pathToTourPage } from "./tour-steps";

export function TourTrigger() {
  const pathname = usePathname();
  const { startTour, isTourCompleted, active } = useTour();
  const [shouldPulse, setShouldPulse] = useState(false);
  const [mounted, setMounted] = useState(false);

  const tourPage = pathToTourPage(pathname);

  // Only show on pages that have a tour defined
  const showButton = tourPage !== null;

  // Check completion status client-side only (after mount)
  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (mounted && tourPage) {
      setShouldPulse(!isTourCompleted(tourPage));
    }
  }, [mounted, tourPage, isTourCompleted]);

  if (!showButton || active) return null;

  function handleClick() {
    if (tourPage) {
      setShouldPulse(false);
      startTour(tourPage);
    }
  }

  return (
    <div className="fixed bottom-6 right-6 z-[9000]">
      {/* Hover tooltip */}
      <div className="group relative">
        <button
          onClick={handleClick}
          aria-label="Take a guided tour"
          className="relative w-12 h-12 rounded-full flex items-center justify-center shadow-lg transition-all duration-300 hover:scale-110"
          style={{
            background: "linear-gradient(135deg, #0f1724, #0a0e18)",
            border: "1px solid rgba(6,182,212,0.35)",
            boxShadow:
              "0 0 20px rgba(6,182,212,0.1), 0 8px 32px rgba(0,0,0,0.4)",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = "rgba(6,182,212,0.6)";
            e.currentTarget.style.boxShadow =
              "0 0 28px rgba(6,182,212,0.2), 0 8px 32px rgba(0,0,0,0.4)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = "rgba(6,182,212,0.35)";
            e.currentTarget.style.boxShadow =
              "0 0 20px rgba(6,182,212,0.1), 0 8px 32px rgba(0,0,0,0.4)";
          }}
        >
          <HelpCircle size={22} style={{ color: "#06b6d4" }} />

          {/* Pulse ring for first-time visitors */}
          {shouldPulse && (
            <span
              className="absolute inset-0 rounded-full animate-ping"
              style={{
                border: "2px solid rgba(6,182,212,0.4)",
                animationDuration: "2s",
              }}
            />
          )}
        </button>

        {/* Tooltip label on hover */}
        <div
          className="absolute bottom-full right-0 mb-2 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none"
          style={{
            background: "#0f1724",
            border: "1px solid rgba(6,182,212,0.2)",
            color: "#94a3b8",
          }}
        >
          Take a guided tour
        </div>
      </div>
    </div>
  );
}
