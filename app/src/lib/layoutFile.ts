// app/src/lib/layoutFile.ts
// Layout export/import file plumbing: the native save/open dialogs inside the
// Tauri shell, a download and a file picker in browser dev. The JSON shape and
// its validation live in store/ui.ts

import { invoke } from "@tauri-apps/api/core";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { isTauri } from "@/lib/endpoint";

const kFileName = "slopstation-layout.json";
const kFilter = [{ name: "Layout JSON", extensions: ["json"] }];

/** Write the layout JSON to a file the user picks; null when cancelled. */
export async function saveLayoutFile(text: string): Promise<string | null> {
  if (!isTauri()) {
    const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = kFileName;
    a.click();
    URL.revokeObjectURL(url);
    return kFileName;
  }
  const path = await saveDialog({ defaultPath: kFileName, filters: kFilter });
  if (path === null) return null;
  await invoke("write_text_file", { path, text });
  return path;
}

/** Read the layout file the user picks; null when cancelled. */
export async function readLayoutFile(): Promise<string | null> {
  if (!isTauri()) {
    const file = await pickFile();
    return file === null ? null : await file.text();
  }
  const path = await openDialog({ multiple: false, directory: false, filters: kFilter });
  if (typeof path !== "string") return null;
  return await invoke<string>("read_text_file", { path });
}

// `new Promise`, not `Promise.withResolvers`: the build targets chrome110,
// which predates it (tsconfig lib ES2022)
function pickFile(): Promise<File | null> {
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json,application/json";
    input.onchange = () => resolve(input.files?.[0] ?? null);
    input.oncancel = () => resolve(null);
    input.click();
  });
}
