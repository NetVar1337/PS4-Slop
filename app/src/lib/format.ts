// app/src/lib/format.ts
// display helpers shared by the views: addresses, image formats, escaped text

import type { ImageFormat } from "./events";

export function hex(va: number, pad = 16): string {
  return va.toString(16).toUpperCase().padStart(pad, "0");
}

/**
 * Canonical unnamed-function label, identical to the engine's
 * disasm::default_function_name(): VA in uppercase hex, no padding.
 */
export function defaultFunctionName(va: number): string {
  return `sub_${va.toString(16).toUpperCase()}`;
}

/**
 * Parse a user-typed address. Hex by default (with or without 0x, separators
 * like ` or _ allowed); returns null for anything that is not a non-negative
 * integer within the safe range.
 */
export function parseAddress(text: string): number | null {
  const clean = text
    .trim()
    .replace(/[`_\s]/g, "")
    .replace(/^0x/i, "");
  if (clean === "" || !/^[0-9a-f]+$/i.test(clean)) return null;
  const value = Number.parseInt(clean, 16);
  return Number.isSafeInteger(value) ? value : null;
}

/** Short format name for headers and the inspector. */
export function formatLabel(format: ImageFormat | undefined, pe32plus?: boolean): string {
  switch (format) {
    case "elf":
      return "ELF";
    case "self":
      return "SELF";
    case "macho":
      return "Mach-O";
    case "pe":
      return pe32plus === undefined ? "PE" : pe32plus ? "PE32+" : "PE32";
    default:
      return "Image";
  }
}

/** Title of the image-browser tab for the loaded format. */
export function browserLabel(format: ImageFormat | undefined): string {
  return format === undefined ? "Image Browser" : `${formatLabel(format)} Browser`;
}

const kEscapes: Record<string, string> = {
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
  "\0": "\\0",
  "\\": "\\\\",
};

/**
 * Render a string one-line: control characters become C escapes so a string
 * containing a newline cannot spill into the next virtualized row.
 */
export function escapeControl(text: string): string {
  let out = "";
  for (const ch of text) {
    const mapped = kEscapes[ch];
    if (mapped !== undefined) {
      out += mapped;
      continue;
    }
    const code = ch.codePointAt(0) ?? 0;
    if (
      code < 0x20 ||
      code === 0x7f ||
      (code >= 0x80 && code < 0xa0) ||
      code === 0x2028 ||
      code === 0x2029
    ) {
      out +=
        code <= 0xff
          ? `\\x${code.toString(16).padStart(2, "0")}`
          : `\\u${code.toString(16).padStart(4, "0")}`;
    } else {
      out += ch;
    }
  }
  return out;
}
