// app/src/lib/openBinary.ts
// file picker, tauri dialog in the shell and a prompt in a plain browser

import { open } from "@tauri-apps/plugin-dialog";
import { isTauri } from "@/lib/endpoint";
import { useDisasm } from "@/store/disasm";

export const kBinaryFilters = [
  {
    name: "Binaries",
    extensions: ["bin", "elf", "self", "prx", "sprx", "exe", "dll", "sys", "efi", "ipa"],
  },
  { name: "PS4 executables", extensions: ["bin", "elf", "self", "prx", "sprx"] },
  { name: "PE executables", extensions: ["exe", "dll", "sys", "efi"] },
  { name: "iOS apps", extensions: ["ipa"] },
  { name: "All files", extensions: ["*"] },
];

export async function openBinary(): Promise<void> {
  let path: string | null;

  if (isTauri()) {
    const picked = await open({
      multiple: false,
      directory: false,
      title: "Open binary for analysis",
      filters: kBinaryFilters,
    });
    path = typeof picked === "string" ? picked : null;
  } else {
    // Browser dev mode has no native dialog
    const typed = window.prompt("Path to binary");
    path = typed !== null && typed.trim() !== "" ? typed.trim() : null;
  }

  if (path !== null) await useDisasm.getState().loadFile(path);
}
