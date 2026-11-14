// app/src/store/memory.ts
// Live memory browsing for the hex editor: regions, a scrollable window over
// one region filled page by page as it scrolls, and writes through the active
// backend (ps4 wire when a console is connected). Everything the view shows
// lives here so switching tabs does not lose the position

import { create } from "zustand";
import { call, errorText } from "@/lib/rpc";

export type Region = {
  base: number;
  size: number;
  protect: number;
  state: number;
  type: number;
};

/** Page size for one read. 4 KiB keeps a scroll responsive over loopback. */
export const kPageBytes = 0x1000;
/**
 * Bytes one scroll window spans. Bounded because a browser caps element height
 * (~33M px); 1 MiB is 65536 rows. Prev/next move the window along the region.
 */
export const kWindowBytes = 0x100000;
/** Pages read concurrently ahead of the viewport. */
const kReadAhead = 2;
/** Hex grid geometry, shared with MemoryView so scroll offsets agree. */
export const kHexCols = 16;
export const kHexRowPx = 19;

type MemoryStore = {
  regions: Region[];
  /** Address the user navigated to (goto, region click). */
  cursor: number;
  /** First byte of the scroll window. */
  windowBase: number;
  /** Bytes in the scroll window. */
  windowSize: number;
  /** Page base -> bytes, or null when the page could not be read. */
  pages: Record<number, Uint8Array | null>;
  /** Text in the goto box, kept across remounts. */
  gotoText: string;
  /** Scroll offset of the hex grid, restored on remount. */
  scrollTop: number;
  /** Bumped by every goto so the grid scrolls the target into view. */
  gotoSeq: number;
  loading: boolean;
  error: string | null;

  loadRegions: () => Promise<void>;
  goto: (addr: number) => void;
  /** Read every not-yet-loaded page overlapping [start, end). */
  ensurePages: (start: number, end: number) => void;
  /** Drop the page cache and re-read what is visible. */
  reload: () => void;
  writeBytes: (addr: number, data: Uint8Array) => Promise<boolean>;
  setGotoText: (text: string) => void;
  setScrollTop: (px: number) => void;
  /** Move the caret without scrolling (the hex grid sets it on click). */
  setCursor: (addr: number) => void;
  reset: () => void;
};

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  const out = new Uint8Array(clean.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(data: Uint8Array): string {
  let s = "";
  for (const b of data) s += b.toString(16).padStart(2, "0").toUpperCase();
  return s;
}

/** PAGE_* protection constants, rendered the way the region table shows them. */
export function protectName(protect: number): string {
  const base = protect & 0xff;
  const names: Record<number, string> = {
    0x01: "NOACCESS",
    0x02: "R",
    0x04: "RW",
    0x08: "WC",
    0x10: "X",
    0x20: "RX",
    0x40: "RWX",
    0x80: "XWC",
  };
  let out = names[base] ?? `0x${protect.toString(16)}`;
  if ((protect & 0x100) !== 0) out += "+G";
  if ((protect & 0x200) !== 0) out += "+NC";
  return out;
}

const alignDown = (v: number, a: number): number => v - (v % a);

/** Window placement for `addr`: inside its region, centred where room allows. */
export function windowFor(
  regions: readonly Region[],
  addr: number,
): { base: number; size: number } {
  const region = regions.find((r) => addr >= r.base && addr < r.base + r.size);
  const page = alignDown(addr, kPageBytes);
  if (region === undefined) return { base: page, size: kWindowBytes };
  const end = region.base + region.size;
  let base = Math.max(region.base, page - kWindowBytes / 2);
  base = Math.max(region.base, Math.min(base, end - kWindowBytes));
  return { base, size: Math.min(kWindowBytes, end - base) };
}

/** Byte at `addr`, or undefined when its page is not loaded / unreadable. */
export function byteAt(pages: Record<number, Uint8Array | null>, addr: number): number | undefined {
  const page = pages[alignDown(addr, kPageBytes)];
  return page?.[addr % kPageBytes];
}

const inflight = new Set<number>();

export const useMemory = create<MemoryStore>((set, get) => {
  const readPage = async (page: number, windowBase: number): Promise<void> => {
    if (inflight.has(page)) return;
    inflight.add(page);
    set({ loading: true });
    try {
      const res = await call<{ hex?: string }>("memory", "read", {
        addr: page,
        len: kPageBytes,
        format: "hex",
      });
      if (get().windowBase !== windowBase) return;
      set((s) => ({ pages: { ...s.pages, [page]: hexToBytes(res.hex ?? "") }, error: null }));
    } catch (e) {
      if (get().windowBase !== windowBase) return;
      set((s) => ({ pages: { ...s.pages, [page]: null }, error: errorText(e) }));
    } finally {
      inflight.delete(page);
      if (inflight.size === 0) set({ loading: false });
    }
  };

  return {
    regions: [],
    cursor: 0,
    windowBase: 0,
    windowSize: 0,
    pages: {},
    gotoText: "",
    scrollTop: 0,
    gotoSeq: 0,
    loading: false,
    error: null,

    loadRegions: async () => {
      try {
        const res = await call<{ regions: Region[] }>("target", "regions");
        // MEM_COMMIT only: reserved and free ranges are not readable, and listing
        // them just gives the user rows that always fail
        const regions = (res.regions ?? []).filter((r) => r.state === 0x1000);
        set({ regions, error: null });
      } catch (e) {
        set({ regions: [], error: errorText(e) });
      }
    },

    goto: (addr) => {
      const { base, size } = windowFor(get().regions, addr);
      const same = base === get().windowBase && size === get().windowSize;
      set({
        cursor: addr,
        windowBase: base,
        windowSize: size,
        gotoSeq: get().gotoSeq + 1,
        // Where the grid should land; a view mounting after the goto (palette
        // jump into the Memory tab) starts there
        scrollTop: Math.floor((addr - base) / kHexCols) * kHexRowPx,
        ...(same ? {} : { pages: {} }),
        error: null,
      });
      get().ensurePages(addr, addr + kPageBytes);
    },

    ensurePages: (start, end) => {
      const { windowBase, windowSize, pages } = get();
      if (windowSize === 0) return;
      const lo = Math.max(windowBase, alignDown(start, kPageBytes));
      const hi = Math.min(windowBase + windowSize, end + kReadAhead * kPageBytes);
      for (let p = lo; p < hi; p += kPageBytes) {
        if (!(p in pages)) void readPage(p, windowBase);
      }
    },

    reload: () => {
      const { cursor } = get();
      set({ pages: {} });
      get().ensurePages(cursor, cursor + kPageBytes);
    },

    writeBytes: async (addr, data) => {
      try {
        await call("memory", "write", { addr, hex: bytesToHex(data) });
      } catch (e) {
        set({ error: `write at 0x${addr.toString(16).toUpperCase()} failed: ${errorText(e)}` });
        return false;
      }
      // Re-read the page so the grid shows what the target actually holds
      const page = alignDown(addr, kPageBytes);
      set((s) => {
        const pages = { ...s.pages };
        delete pages[page];
        return { pages, error: null };
      });
      await readPage(page, get().windowBase);
      return true;
    },

    setGotoText: (gotoText) => set({ gotoText }),
    setScrollTop: (scrollTop) => set({ scrollTop }),
    setCursor: (addr) => set({ cursor: addr }),

    reset: () =>
      set({
        regions: [],
        pages: {},
        cursor: 0,
        windowBase: 0,
        windowSize: 0,
        scrollTop: 0,
        error: null,
      }),
  };
});
