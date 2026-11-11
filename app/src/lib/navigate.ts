// app/src/lib/navigate.ts
// cross-view jumps: following an address from strings, registers, the image
// browser or the palette lands on the view that shows it

import { useDisasm } from "@/store/disasm";
import { useMemory } from "@/store/memory";
import { useUi } from "@/store/ui";

export function showInDisassembly(va: number): void {
  useUi.getState().setWorkspaceTab("disassembly");
  void useDisasm.getState().gotoAddress(va);
}

export function showInMemory(addr: number): void {
  useUi.getState().setWorkspaceTab("memory");
  useMemory.getState().goto(addr);
}
