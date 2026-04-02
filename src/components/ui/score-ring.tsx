"use client";

import { useEffect, useRef, useState } from "react";
import clsx from "clsx";

interface ScoreRingProps {
  score: number;
  label?: string;
  size?: number;
}

function getThreatLevel(score: number) {
  if (score <= 30) return { text: "SAFE", color: "var(--color-safe)", class: "text-safe" };
  if (score <= 60) return { text: "CAUTION", color: "var(--color-caution)", class: "text-caution" };
  if (score <= 80) return { text: "DANGER", color: "var(--color-danger)", class: "text-danger" };
  return { text: "CRITICAL", color: "var(--color-critical)", class: "text-critical" };
}

export function ScoreRing({ score, label, size = 200 }: ScoreRingProps) {
  const [animatedScore, setAnimatedScore] = useState(0);
  const rafRef = useRef<number | null>(null);
  const threat = getThreatLevel(score);

  const strokeWidth = size * 0.06;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = (animatedScore / 100) * circumference;
  const center = size / 2;

  useEffect(() => {
    let start: number | null = null;
    const duration = 1400;

    function animate(timestamp: number) {
      if (!start) start = timestamp;
      const elapsed = timestamp - start;
      const t = Math.min(elapsed / duration, 1);
      // ease-out cubic
      const eased = 1 - Math.pow(1 - t, 3);
      setAnimatedScore(Math.round(eased * score));
      if (t < 1) {
        rafRef.current = requestAnimationFrame(animate);
      }
    }

    rafRef.current = requestAnimationFrame(animate);
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [score]);

  const isCritical = score > 80;

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative" style={{ width: size, height: size }}>
        {/* Glow layer */}
        <div
          className={clsx("absolute inset-0 rounded-full blur-xl opacity-30", isCritical && "threat-pulse")}
          style={{ backgroundColor: threat.color }}
        />

        <svg
          width={size}
          height={size}
          className="score-ring relative z-10 -rotate-90"
          style={{ color: threat.color }}
        >
          {/* Background track */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke="var(--color-slate-deep)"
            strokeWidth={strokeWidth}
          />
          {/* Score arc */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke={threat.color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={circumference - progress}
            strokeLinecap="round"
            className="transition-all duration-100"
          />
          {/* Subtle inner ring */}
          <circle
            cx={center}
            cy={center}
            r={radius - strokeWidth * 1.5}
            fill="none"
            stroke="var(--color-border)"
            strokeWidth={1}
            opacity={0.4}
          />
        </svg>

        {/* Center content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center z-20">
          <span
            className={clsx("font-mono font-bold leading-none", threat.class)}
            style={{ fontSize: size * 0.28 }}
          >
            {animatedScore}
          </span>
          <span
            className={clsx(
              "font-mono font-semibold tracking-[0.2em] uppercase mt-1",
              threat.class,
              isCritical && "threat-pulse"
            )}
            style={{ fontSize: size * 0.08 }}
          >
            {threat.text}
          </span>
        </div>
      </div>

      {label && (
        <span className="text-text-secondary text-sm font-mono tracking-wide">
          {label}
        </span>
      )}
    </div>
  );
}
