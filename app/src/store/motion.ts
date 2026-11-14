// app/src/store/motion.ts
// motion preference, the os reduced motion setting is the default not the law

import { create } from "zustand";
import type { Key } from "@/i18n/en";

export type MotionPref = "on" | "auto" | "off";

export const kMotionOptions: readonly { id: MotionPref; labelKey: Key; hintKey: Key }[] = [
  { id: "on", labelKey: "motion.on", hintKey: "motion.onHint" },
  { id: "auto", labelKey: "motion.auto", hintKey: "motion.autoHint" },
  { id: "off", labelKey: "motion.off", hintKey: "motion.offHint" },
];

const kStorageKey = "reverse-slop.motion";

function initial(): MotionPref {
  const saved = localStorage.getItem(kStorageKey);
  // Unset means "auto": the OS reduced-motion setting decides until the user
  // explicitly overrides it here
  return saved === "on" || saved === "auto" || saved === "off" ? saved : "auto";
}

/** CSS reads `data-motion` on <html>; see the motion section of app.css. */
function apply(pref: MotionPref): void {
  document.documentElement.setAttribute("data-motion", pref);
}

/** Whether the OS currently asks for reduced motion, for the Settings hint. */
export function osPrefersReduced(): boolean {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

type MotionStore = {
  motion: MotionPref;
  setMotion: (pref: MotionPref) => void;
};

export const useMotion = create<MotionStore>((set) => {
  const motion = initial();
  apply(motion);
  return {
    motion,
    setMotion: (pref) => {
      apply(pref);
      localStorage.setItem(kStorageKey, pref);
      set({ motion: pref });
    },
  };
});
