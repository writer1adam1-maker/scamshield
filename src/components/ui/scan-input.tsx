"use client";

import { useState, useCallback, useRef } from "react";
import {
  Shield,
  Link,
  FileText,
  Image,
  Upload,
  Loader2,
  ScanLine,
} from "lucide-react";
import clsx from "clsx";

type InputTab = "url" | "text" | "screenshot";

interface ScanInputProps {
  onScan?: (data: { type: InputTab; content: string; file?: File }) => void;
  isLoading?: boolean;
  progress?: number;
}

export function ScanInput({ onScan, isLoading = false, progress = 0 }: ScanInputProps) {
  const [activeTab, setActiveTab] = useState<InputTab>("url");
  const [content, setContent] = useState("");
  const [dragActive, setDragActive] = useState(false);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const tabs: { id: InputTab; label: string; icon: typeof Link }[] = [
    { id: "url", label: "URL", icon: Link },
    { id: "text", label: "Text / Email", icon: FileText },
    { id: "screenshot", label: "Screenshot", icon: Image },
  ];

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") setDragActive(true);
    else if (e.type === "dragleave") setDragActive(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    const file = e.dataTransfer.files?.[0];
    if (file && file.type.startsWith("image/")) {
      setUploadedFile(file);
      setActiveTab("screenshot");
    }
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) setUploadedFile(file);
  };

  const handleSubmit = () => {
    if (isLoading) return;
    if (activeTab === "screenshot" && uploadedFile) {
      onScan?.({ type: "screenshot", content: uploadedFile.name, file: uploadedFile });
    } else if (content.trim()) {
      onScan?.({ type: activeTab, content: content.trim() });
    }
  };

  const placeholders: Record<InputTab, string> = {
    url: "Paste a suspicious URL here... e.g. https://amaz0n-verify.sketchy.link/account",
    text: "Paste a suspicious email, text message, or DM...\n\nExample: \"URGENT: Your account has been compromised. Click here to verify your identity immediately or your account will be permanently deleted.\"",
    screenshot: "",
  };

  const canSubmit =
    activeTab === "screenshot" ? !!uploadedFile : content.trim().length > 0;

  return (
    <div className="w-full">
      {/* Tab selector */}
      <div className="flex gap-1 mb-4 p-1 rounded-xl bg-abyss/80 border border-border w-fit">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={clsx(
                "flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200",
                activeTab === tab.id
                  ? "bg-shield/10 text-shield border border-shield/20"
                  : "text-text-muted hover:text-text-secondary"
              )}
            >
              <Icon size={14} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Input area with animated gradient border */}
      <div className="relative group">
        {/* Animated gradient border */}
        <div
          className={clsx(
            "absolute -inset-[1px] rounded-2xl opacity-40 group-hover:opacity-70 transition-opacity duration-500",
            isLoading && "opacity-100"
          )}
          style={{
            background:
              "linear-gradient(135deg, var(--color-shield), var(--color-safe), var(--color-shield), var(--color-shield-dim))",
            backgroundSize: "300% 300%",
            animation: "gradient-shift 4s ease infinite",
          }}
        />

        <div className="relative rounded-2xl bg-obsidian overflow-hidden">
          {/* Scan animation overlay */}
          {isLoading && (
            <div className="absolute inset-0 z-10 pointer-events-none overflow-hidden rounded-2xl">
              <div
                className="absolute left-0 right-0 h-[2px] bg-shield/80 shadow-[0_0_20px_var(--color-shield)]"
                style={{
                  animation: "scanline 2s ease-in-out infinite",
                }}
              />
              <div className="absolute inset-0 bg-shield/[0.02]" />
            </div>
          )}

          {/* Text input */}
          {activeTab !== "screenshot" ? (
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder={placeholders[activeTab]}
              disabled={isLoading}
              rows={5}
              className={clsx(
                "w-full bg-transparent p-5 text-text-primary placeholder:text-text-muted/60",
                "resize-none outline-none font-mono text-sm leading-relaxed",
                "disabled:opacity-50"
              )}
            />
          ) : (
            /* Screenshot upload zone */
            <div
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={clsx(
                "flex flex-col items-center justify-center p-10 cursor-pointer transition-all duration-200 min-h-[180px]",
                dragActive
                  ? "bg-shield/[0.06] border-2 border-dashed border-shield/40"
                  : "border-2 border-dashed border-border hover:border-shield/20"
              )}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                onChange={handleFileChange}
                className="hidden"
              />

              {uploadedFile ? (
                <div className="flex items-center gap-3 text-text-secondary">
                  <Image size={20} className="text-shield" />
                  <span className="font-mono text-sm">{uploadedFile.name}</span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setUploadedFile(null);
                    }}
                    className="text-text-muted hover:text-danger text-xs"
                  >
                    Remove
                  </button>
                </div>
              ) : (
                <>
                  <Upload
                    size={28}
                    className={clsx(
                      "mb-3 transition-colors",
                      dragActive ? "text-shield" : "text-text-muted"
                    )}
                  />
                  <p className="text-sm text-text-secondary mb-1">
                    Drop a screenshot here or click to upload
                  </p>
                  <p className="text-xs text-text-muted">PNG, JPG, or WEBP up to 10MB</p>
                </>
              )}
            </div>
          )}

          {/* Bottom action bar */}
          <div className="flex items-center justify-between p-4 border-t border-border/50">
            {/* Progress indicator when loading */}
            {isLoading ? (
              <div className="flex items-center gap-3 flex-1 mr-4">
                <div className="flex-1 h-1.5 rounded-full bg-slate-deep overflow-hidden">
                  <div
                    className="h-full rounded-full bg-shield transition-all duration-500 ease-out"
                    style={{ width: `${progress}%` }}
                  />
                </div>
                <span className="text-xs font-mono text-shield shrink-0">
                  {progress}%
                </span>
              </div>
            ) : (
              <div className="flex items-center gap-2 text-xs text-text-muted">
                <ScanLine size={12} />
                <span className="font-mono">VERIDICT multi-layer analysis</span>
              </div>
            )}

            {/* Analyze button */}
            <button
              onClick={handleSubmit}
              disabled={isLoading || !canSubmit}
              className={clsx(
                "relative flex items-center gap-2 px-6 py-2.5 rounded-xl font-semibold text-sm transition-all duration-200",
                "disabled:opacity-30 disabled:cursor-not-allowed",
                canSubmit && !isLoading
                  ? "bg-shield text-void hover:bg-shield-dim shield-glow"
                  : "bg-slate-deep text-text-muted"
              )}
            >
              {isLoading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Shield size={16} />
                  Analyze
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Inline gradient animation keyframes */}
      <style jsx>{`
        @keyframes gradient-shift {
          0% { background-position: 0% 50%; }
          50% { background-position: 100% 50%; }
          100% { background-position: 0% 50%; }
        }
      `}</style>
    </div>
  );
}
