"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { ChevronLeft, ChevronRight, X, Shield } from "lucide-react";
import { useTour } from "./tour-provider";

// ---------------------------------------------------------------------------
// Geometry helpers
// ---------------------------------------------------------------------------

interface Rect {
  top: number;
  left: number;
  width: number;
  height: number;
  bottom: number;
  right: number;
}

type Placement = "top" | "bottom" | "left" | "right";

const GAP = 14; // space between target and tooltip
const TOOLTIP_MAX_W = 370;

function bestPlacement(target: Rect, tooltipH: number): Placement {
  const spaceAbove = target.top;
  const spaceBelow = window.innerHeight - target.bottom;
  const spaceLeft = target.left;
  const spaceRight = window.innerWidth - target.right;

  // Prefer below, then above, then right, then left
  if (spaceBelow >= tooltipH + GAP + 20) return "bottom";
  if (spaceAbove >= tooltipH + GAP + 20) return "top";
  if (spaceRight >= TOOLTIP_MAX_W + GAP + 20) return "right";
  if (spaceLeft >= TOOLTIP_MAX_W + GAP + 20) return "left";
  return "bottom"; // fallback
}

function tooltipPosition(
  target: Rect,
  placement: Placement,
  tooltipW: number,
  tooltipH: number,
): { top: number; left: number } {
  let top = 0;
  let left = 0;

  switch (placement) {
    case "bottom":
      top = target.bottom + GAP;
      left = target.left + target.width / 2 - tooltipW / 2;
      break;
    case "top":
      top = target.top - tooltipH - GAP;
      left = target.left + target.width / 2 - tooltipW / 2;
      break;
    case "right":
      top = target.top + target.height / 2 - tooltipH / 2;
      left = target.right + GAP;
      break;
    case "left":
      top = target.top + target.height / 2 - tooltipH / 2;
      left = target.left - tooltipW - GAP;
      break;
  }

  // Clamp within viewport
  const padding = 12;
  left = Math.max(padding, Math.min(left, window.innerWidth - tooltipW - padding));
  top = Math.max(padding, Math.min(top, window.innerHeight - tooltipH - padding));

  return { top, left };
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function TourTooltip() {
  const {
    active,
    currentStep,
    stepIndex,
    totalSteps,
    nextStep,
    prevStep,
    skipTour,
  } = useTour();

  const tooltipRef = useRef<HTMLDivElement>(null);
  const [targetRect, setTargetRect] = useState<Rect | null>(null);
  const [pos, setPos] = useState({ top: 0, left: 0 });
  const [visible, setVisible] = useState(false);

  // Locate target element and compute position
  const recalculate = useCallback(() => {
    if (!currentStep) return;

    const el = document.querySelector(`[data-tour="${currentStep.target}"]`);
    if (!el) {
      // Target not found — skip step silently or show centered
      setTargetRect(null);
      setPos({
        top: window.innerHeight / 2 - 100,
        left: window.innerWidth / 2 - TOOLTIP_MAX_W / 2,
      });
      setVisible(true);
      return;
    }

    // Scroll into view smoothly
    el.scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });

    // Wait a tick for scroll to settle
    requestAnimationFrame(() => {
      const rect = el.getBoundingClientRect();
      const r: Rect = {
        top: rect.top,
        left: rect.left,
        width: rect.width,
        height: rect.height,
        bottom: rect.bottom,
        right: rect.right,
      };
      setTargetRect(r);

      const tooltipEl = tooltipRef.current;
      const tooltipH = tooltipEl?.offsetHeight ?? 200;
      const tooltipW = Math.min(TOOLTIP_MAX_W, window.innerWidth - 24);
      const placement = bestPlacement(r, tooltipH);
      setPos(tooltipPosition(r, placement, tooltipW, tooltipH));
      setVisible(true);
    });
  }, [currentStep]);

  // Recalculate whenever step changes
  useEffect(() => {
    if (!active || !currentStep) {
      setVisible(false);
      return;
    }
    setVisible(false);
    // Small delay to allow for any DOM mutations after step change
    const timer = setTimeout(recalculate, 150);
    return () => clearTimeout(timer);
  }, [active, currentStep, recalculate]);

  // Recalculate on resize / scroll
  useEffect(() => {
    if (!active) return;
    const handler = () => recalculate();
    window.addEventListener("resize", handler);
    window.addEventListener("scroll", handler, true);
    return () => {
      window.removeEventListener("resize", handler);
      window.removeEventListener("scroll", handler, true);
    };
  }, [active, recalculate]);

  // Keyboard navigation
  useEffect(() => {
    if (!active) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") skipTour();
      else if (e.key === "ArrowRight" || e.key === "Enter") nextStep();
      else if (e.key === "ArrowLeft") prevStep();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [active, skipTour, nextStep, prevStep]);

  if (!active || !currentStep) return null;

  // Spotlight cutout SVG dimensions
  const pad = 8; // padding around target element for spotlight
  const svgTarget = targetRect
    ? {
        x: targetRect.left - pad,
        y: targetRect.top - pad,
        w: targetRect.width + pad * 2,
        h: targetRect.height + pad * 2,
        rx: 12,
      }
    : null;

  return (
    <>
      {/* Overlay backdrop with spotlight cutout */}
      <div className="fixed inset-0 z-[9998]" style={{ pointerEvents: "auto" }}>
        <svg
          className="absolute inset-0 w-full h-full"
          style={{ pointerEvents: "none" }}
        >
          <defs>
            <mask id="tour-spotlight-mask">
              <rect x="0" y="0" width="100%" height="100%" fill="white" />
              {svgTarget && (
                <rect
                  x={svgTarget.x}
                  y={svgTarget.y}
                  width={svgTarget.w}
                  height={svgTarget.h}
                  rx={svgTarget.rx}
                  fill="black"
                />
              )}
            </mask>
          </defs>
          <rect
            x="0"
            y="0"
            width="100%"
            height="100%"
            fill="rgba(0,0,0,0.72)"
            mask="url(#tour-spotlight-mask)"
          />
        </svg>

        {/* Spotlight glow ring */}
        {svgTarget && (
          <div
            className="absolute rounded-xl pointer-events-none"
            style={{
              left: svgTarget.x - 2,
              top: svgTarget.y - 2,
              width: svgTarget.w + 4,
              height: svgTarget.h + 4,
              boxShadow: "0 0 0 2px rgba(6,182,212,0.5), 0 0 24px rgba(6,182,212,0.2)",
              transition: "all 0.35s cubic-bezier(0.4,0,0.2,1)",
            }}
          />
        )}

        {/* Click-through zone over the target so it stays interactive-looking */}
        {svgTarget && (
          <div
            className="absolute"
            style={{
              left: svgTarget.x,
              top: svgTarget.y,
              width: svgTarget.w,
              height: svgTarget.h,
              pointerEvents: "none",
            }}
          />
        )}

        {/* Click the backdrop to dismiss */}
        <div
          className="absolute inset-0"
          style={{ pointerEvents: "auto", background: "transparent" }}
          onClick={skipTour}
        />
      </div>

      {/* Tooltip card */}
      <div
        ref={tooltipRef}
        className="fixed z-[9999]"
        style={{
          top: pos.top,
          left: pos.left,
          width: `min(${TOOLTIP_MAX_W}px, calc(100vw - 24px))`,
          opacity: visible ? 1 : 0,
          transform: visible ? "translateY(0)" : "translateY(8px)",
          transition: "opacity 0.3s ease, transform 0.3s ease",
          pointerEvents: "auto",
        }}
      >
        <div
          className="rounded-2xl p-5 shadow-2xl border"
          style={{
            background: "linear-gradient(135deg, #0f1724 0%, #0a0e18 100%)",
            borderColor: "rgba(6,182,212,0.25)",
            boxShadow:
              "0 0 40px rgba(6,182,212,0.08), 0 20px 60px rgba(0,0,0,0.5)",
          }}
        >
          {/* Header */}
          <div className="flex items-start justify-between gap-3 mb-3">
            <div className="flex items-center gap-2">
              <div
                className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
                style={{
                  background: "rgba(6,182,212,0.12)",
                  border: "1px solid rgba(6,182,212,0.25)",
                }}
              >
                <Shield size={14} style={{ color: "#06b6d4" }} />
              </div>
              <h3
                className="text-sm font-bold leading-tight"
                style={{ color: "#e2e8f0" }}
              >
                {currentStep.title}
              </h3>
            </div>
            <button
              onClick={skipTour}
              className="p-1 rounded-lg transition-colors shrink-0"
              style={{ color: "#64748b" }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.color = "#94a3b8")
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.color = "#64748b")
              }
              aria-label="Close tour"
            >
              <X size={16} />
            </button>
          </div>

          {/* Description */}
          <p
            className="text-[13px] leading-relaxed mb-4"
            style={{ color: "#94a3b8" }}
          >
            {currentStep.description}
          </p>

          {/* Footer: step counter + navigation */}
          <div className="flex items-center justify-between">
            {/* Step counter */}
            <span
              className="text-[11px] font-mono"
              style={{ color: "#475569" }}
            >
              Step {stepIndex + 1} of {totalSteps}
            </span>

            {/* Buttons */}
            <div className="flex items-center gap-2">
              {/* Skip */}
              <button
                onClick={skipTour}
                className="px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
                style={{
                  color: "#64748b",
                  background: "transparent",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.color = "#94a3b8";
                  e.currentTarget.style.background = "rgba(100,116,139,0.1)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.color = "#64748b";
                  e.currentTarget.style.background = "transparent";
                }}
              >
                Skip tour
              </button>

              {/* Back */}
              {stepIndex > 0 && (
                <button
                  onClick={prevStep}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
                  style={{
                    color: "#94a3b8",
                    border: "1px solid rgba(100,116,139,0.3)",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = "rgba(6,182,212,0.4)";
                    e.currentTarget.style.color = "#e2e8f0";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = "rgba(100,116,139,0.3)";
                    e.currentTarget.style.color = "#94a3b8";
                  }}
                >
                  <ChevronLeft size={13} />
                  Back
                </button>
              )}

              {/* Next / Finish */}
              <button
                onClick={nextStep}
                className="flex items-center gap-1 px-4 py-1.5 rounded-lg text-xs font-bold transition-all"
                style={{
                  background: "#06b6d4",
                  color: "#0a0e18",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = "#22d3ee";
                  e.currentTarget.style.boxShadow = "0 0 16px rgba(6,182,212,0.4)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "#06b6d4";
                  e.currentTarget.style.boxShadow = "none";
                }}
              >
                {stepIndex < totalSteps - 1 ? (
                  <>
                    Next
                    <ChevronRight size={13} />
                  </>
                ) : (
                  "Finish"
                )}
              </button>
            </div>
          </div>

          {/* Progress bar */}
          <div
            className="mt-3 h-1 rounded-full overflow-hidden"
            style={{ background: "rgba(100,116,139,0.15)" }}
          >
            <div
              className="h-full rounded-full transition-all duration-500 ease-out"
              style={{
                width: `${((stepIndex + 1) / totalSteps) * 100}%`,
                background: "linear-gradient(90deg, #06b6d4, #22d3ee)",
              }}
            />
          </div>
        </div>
      </div>
    </>
  );
}
