// app/src/lib/ps4debug.ts
// Bundled ps4debug-NG payload: status, latest release check, download, save.

import { invoke } from "@tauri-apps/api/core";
import { isTauri } from "@/lib/endpoint";

export type PayloadInfo = {
  tag: string;
  name: string;
  asset: string;
  url: string;
  sha256: string;
  path: string;
  source: string;
};

export type PayloadStatus = { bundled: PayloadInfo | null; local: PayloadInfo | null };

/** Bundled/local payload, null outside the Tauri shell. */
export async function payloadStatus(): Promise<PayloadStatus | null> {
  if (!isTauri()) return null;
  try {
    return await invoke<PayloadStatus>("ps4debug_payload");
  } catch {
    return null;
  }
}

export async function payloadLatest(): Promise<PayloadInfo> {
  return invoke<PayloadInfo>("ps4debug_payload_latest");
}

export async function payloadDownload(): Promise<PayloadInfo> {
  return invoke<PayloadInfo>("ps4debug_payload_download");
}

export async function payloadSave(source: string, dest: string): Promise<void> {
  await invoke("ps4debug_payload_save", { source, dest });
}
