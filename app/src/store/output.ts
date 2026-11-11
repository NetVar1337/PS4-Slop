// app/src/store/output.ts
// output pane, lines live in the engine ring so a reconnect replays what was
// missed via the seq cursor

import { create } from "zustand";
import * as events from "@/lib/events";
import { call } from "@/lib/rpc";

export type OutputLine = { seq: number; ms: number; text: string };

export const kMaxLines = 4096;
/**
 * Streamed lines are coalesced and committed at most once per this interval.
 * Committing per line copied the 4096-entry ring for every frame, quadratic in
 * a reconnect burst; batching makes a burst one copy per flush.
 */
export const kFlushMs = 16;

type OutputStore = {
  lines: OutputLine[];
  revision: number;
  clear: () => Promise<void>;
  attach: () => () => void;
  replayFrom: (revision: number) => Promise<void>;
  /** Commit buffered lines now (tests and teardown). */
  flush: () => void;
};

let pending: OutputLine[] = [];
let pendingRevision = 0;
let flushTimer: ReturnType<typeof setTimeout> | undefined;

/** Append `extra` to `lines`, keeping only the newest kMaxLines. */
function appendBounded(lines: OutputLine[], extra: OutputLine[]): OutputLine[] {
  if (extra.length >= kMaxLines) return extra.slice(-kMaxLines);
  const keep = Math.max(0, lines.length + extra.length - kMaxLines);
  return keep === 0 ? lines.concat(extra) : lines.slice(keep).concat(extra);
}

export const useOutput = create<OutputStore>((set, get) => ({
  lines: [],
  revision: 0,

  flush: () => {
    clearTimeout(flushTimer);
    flushTimer = undefined;
    if (pending.length === 0) return;
    const batch = pending;
    pending = [];
    set((s) => ({
      lines: appendBounded(s.lines, batch),
      revision: Math.max(s.revision, pendingRevision),
    }));
  },

  attach: () => {
    const offOutput = events.on("output", (line) => {
      // Out-of-order or duplicate frames (reconnect overlap) are dropped by
      // sequence rather than deduplicated by text
      const head = Math.max(get().revision, pendingRevision);
      if (line.seq <= head) return;
      pending.push(line);
      pendingRevision = line.seq;
      // A burst bigger than the ring only keeps its tail anyway
      if (pending.length > kMaxLines) pending = pending.slice(-kMaxLines);
      flushTimer ??= setTimeout(() => get().flush(), kFlushMs);
    });

    const offClear = events.on("output.cleared", () => {
      pending = [];
      pendingRevision = 0;
      set({ lines: [], revision: 0 });
    });

    // On (re)connect the engine tells us where its ring is; pull the gap
    const offHello = events.on("hello", ({ output_revision }) => {
      get().flush();
      if (output_revision < get().revision) {
        pendingRevision = 0;
        set({ lines: [], revision: 0 });
      }
      void get().replayFrom(
        get().revision > 0 ? get().revision : Math.max(0, output_revision - kMaxLines),
      );
    });
    return () => {
      get().flush();
      offOutput();
      offClear();
      offHello();
    };
  },

  replayFrom: async (revision) => {
    try {
      const res = await call<{ revision: number; lines: OutputLine[] }>("app", "output", {
        since: revision,
      });
      if (res.lines.length === 0) return;
      get().flush();
      set((s) => ({
        lines: appendBounded(
          s.lines,
          res.lines.filter((l) => l.seq > s.revision),
        ),
        revision: Math.max(s.revision, res.revision),
      }));
      pendingRevision = Math.max(pendingRevision, get().revision);
    } catch {
      // Nothing to show is better than a thrown error in a log pane
    }
  },

  clear: async () => {
    await call("app", "output_clear");
    pending = [];
    pendingRevision = 0;
    set({ lines: [], revision: 0 });
  },
}));
