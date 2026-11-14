// app/src/lib/shell.ts
// OS file-manager hand-off for the two support paths: the engine log from the
// crash banner and the data dir from Settings (app/src-tauri/src/lib.rs)

import { invoke } from "@tauri-apps/api/core";
import { isTauri } from "@/lib/endpoint";

/** Reveal a file or open a folder in File Explorer. No-op in browser dev. */
export async function openPath(path: string): Promise<void> {
  if (!isTauri() || path === "") return;
  await invoke("open_path", { path });
}
