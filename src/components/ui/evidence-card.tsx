"use client";

import { useState } from "react";
import {
  Link,
  Mail,
  Clock,
  Globe,
  FileText,
  AlertTriangle,
  ChevronDown,
  type LucideIcon,
} from "lucide-react";
import clsx from "clsx";

export type EvidenceType = "url" | "email" | "timing" | "domain" | "content" | "other";
type SeverityLevel = "info" | "low" | "medium" | "high" | "critical";

interface EvidenceCardProps {
  type: EvidenceType;
  title: string;
  description: string;
  severity: SeverityLevel;
  details?: string;
  className?: string;
}

const typeIcons: Record<EvidenceType, LucideIcon> = {
  url: Link,
  email: Mail,
  timing: Clock,
  domain: Globe,
  content: FileText,
  other: AlertTriangle,
};

const severityColors: Record<SeverityLevel, { dot: string; border: string }> = {
  info: { dot: "bg-text-muted", border: "border-l-text-muted" },
  low: { dot: "bg-safe", border: "border-l-safe" },
  medium: { dot: "bg-caution", border: "border-l-caution" },
  high: { dot: "bg-danger", border: "border-l-danger" },
  critical: { dot: "bg-critical", border: "border-l-critical" },
};

export function EvidenceCard({
  type,
  title,
  description,
  severity,
  details,
  className,
}: EvidenceCardProps) {
  const [expanded, setExpanded] = useState(false);
  const Icon = typeIcons[type];
  const sev = severityColors[severity];

  return (
    <div
      className={clsx(
        "glass-card border-l-2 p-4 group hover:border-border-bright transition-colors duration-200",
        sev.border,
        className
      )}
    >
      <div className="flex items-start gap-3">
        {/* Icon */}
        <div className="shrink-0 mt-0.5 p-2 rounded-lg bg-slate-deep/60 text-text-secondary group-hover:text-shield transition-colors">
          <Icon size={16} />
        </div>

        <div className="flex-1 min-w-0">
          {/* Header row */}
          <div className="flex items-center gap-2 mb-1">
            <h4 className="text-sm font-semibold text-text-primary truncate">{title}</h4>
            <span className="shrink-0 flex items-center gap-1.5">
              <span className={clsx("w-2 h-2 rounded-full", sev.dot)} />
              <span className="text-[10px] font-mono uppercase text-text-muted tracking-wider">
                {severity}
              </span>
            </span>
          </div>

          {/* Description */}
          <p className="text-sm text-text-secondary leading-relaxed">{description}</p>

          {/* Expandable details */}
          {details && (
            <>
              <button
                onClick={() => setExpanded(!expanded)}
                className="flex items-center gap-1 mt-2 text-xs font-mono text-shield/70 hover:text-shield transition-colors"
              >
                <ChevronDown
                  size={12}
                  className={clsx("transition-transform duration-200", expanded && "rotate-180")}
                />
                {expanded ? "Hide details" : "View details"}
              </button>

              <div
                className={clsx(
                  "overflow-hidden transition-all duration-300 ease-in-out",
                  expanded ? "max-h-96 opacity-100 mt-2" : "max-h-0 opacity-0"
                )}
              >
                <div className="p-3 rounded-lg bg-abyss/80 border border-border text-xs font-mono text-text-secondary leading-relaxed whitespace-pre-wrap">
                  {details}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
