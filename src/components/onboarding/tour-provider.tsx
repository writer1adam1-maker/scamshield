"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import type { TourPage, TourStep } from "./tour-steps";
import { TOUR_STEPS } from "./tour-steps";

// ---------------------------------------------------------------------------
// Context value
// ---------------------------------------------------------------------------

interface TourContextValue {
  /** Whether any tour is currently active */
  active: boolean;
  /** Which page tour is running (null when inactive) */
  page: TourPage | null;
  /** Current step index (0-based) */
  stepIndex: number;
  /** Current step data (null when inactive) */
  currentStep: TourStep | null;
  /** Total steps for the running tour */
  totalSteps: number;
  /** Start (or restart) a tour for a given page */
  startTour: (page: TourPage) => void;
  /** Advance to the next step; ends tour if at last step */
  nextStep: () => void;
  /** Go back one step (no-op on first step) */
  prevStep: () => void;
  /** Skip / close the tour and mark it completed */
  skipTour: () => void;
  /** Reset a page's tour so it shows again for first-timers */
  resetTour: (page: TourPage) => void;
  /** Check whether a specific page tour has been completed */
  isTourCompleted: (page: TourPage) => boolean;
}

const TourContext = createContext<TourContextValue | null>(null);

// ---------------------------------------------------------------------------
// localStorage helpers
// ---------------------------------------------------------------------------

const STORAGE_PREFIX = "ss_tour_completed_";

function markCompleted(page: TourPage) {
  try {
    localStorage.setItem(`${STORAGE_PREFIX}${page}`, "1");
  } catch {
    /* ignore */
  }
}

function isCompleted(page: TourPage): boolean {
  try {
    return localStorage.getItem(`${STORAGE_PREFIX}${page}`) === "1";
  } catch {
    return false;
  }
}

function clearCompleted(page: TourPage) {
  try {
    localStorage.removeItem(`${STORAGE_PREFIX}${page}`);
  } catch {
    /* ignore */
  }
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export function TourProvider({ children }: { children: React.ReactNode }) {
  const [active, setActive] = useState(false);
  const [page, setPage] = useState<TourPage | null>(null);
  const [stepIndex, setStepIndex] = useState(0);

  // Derive current step list from the active page
  const steps: TourStep[] = page ? TOUR_STEPS[page] ?? [] : [];
  const totalSteps = steps.length;
  const currentStep = active && steps.length > 0 ? steps[stepIndex] ?? null : null;

  // Lock body scroll while tour is active
  useEffect(() => {
    if (active) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "";
    }
    return () => {
      document.body.style.overflow = "";
    };
  }, [active]);

  const startTour = useCallback((p: TourPage) => {
    setPage(p);
    setStepIndex(0);
    setActive(true);
  }, []);

  const nextStep = useCallback(() => {
    setStepIndex((prev) => {
      const next = prev + 1;
      if (next >= steps.length) {
        // Tour finished
        setActive(false);
        if (page) markCompleted(page);
        return 0;
      }
      return next;
    });
  }, [steps.length, page]);

  const prevStep = useCallback(() => {
    setStepIndex((prev) => Math.max(0, prev - 1));
  }, []);

  const skipTour = useCallback(() => {
    setActive(false);
    if (page) markCompleted(page);
    setStepIndex(0);
  }, [page]);

  const resetTour = useCallback((p: TourPage) => {
    clearCompleted(p);
  }, []);

  const isTourCompleted = useCallback((p: TourPage) => isCompleted(p), []);

  const value = useMemo<TourContextValue>(
    () => ({
      active,
      page,
      stepIndex,
      currentStep,
      totalSteps,
      startTour,
      nextStep,
      prevStep,
      skipTour,
      resetTour,
      isTourCompleted,
    }),
    [
      active,
      page,
      stepIndex,
      currentStep,
      totalSteps,
      startTour,
      nextStep,
      prevStep,
      skipTour,
      resetTour,
      isTourCompleted,
    ],
  );

  return <TourContext.Provider value={value}>{children}</TourContext.Provider>;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useTour(): TourContextValue {
  const ctx = useContext(TourContext);
  if (!ctx) throw new Error("useTour must be used within <TourProvider>");
  return ctx;
}
