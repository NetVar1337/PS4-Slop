// app/src/store/types.ts
// Struct/enum catalog mirror for the struct editor. The engine owns the
// catalog (types tool) and persists it per binary hash; every mutation bumps
// its generation, which invalidates decompiled functions, so the store keeps
// a counter the editor shows as "decompiler cache invalidated"

import { create } from "zustand";
import { parseAddress } from "@/lib/format";
import { call, errorText } from "@/lib/rpc";

export type StructField = {
  name: string;
  type: string;
  offset: number;
  size: number;
  array_count: number;
};

export type StructDef = {
  name: string;
  size: number;
  packed: boolean;
  fields: StructField[];
};

export type EnumValue = { name: string; value: number };

export type EnumDef = { name: string; underlying: string; values: EnumValue[] };

/** types.read_field result: every width is a coercion of the same bytes. */
export type FieldValue = {
  hex: string;
  uint: number;
  int: number;
  double: number;
  source: string;
};

export type FieldRead = FieldValue | { error: string };

/** The engine has no remove_member/rename_member: rebuild the struct with declare. */
export function declOf(name: string, fields: readonly StructField[], packed: boolean): string {
  const body = fields
    .map((f) => `${f.type} ${f.name}${f.array_count > 0 ? `[${f.array_count}]` : ""};`)
    .join(" ");
  return `struct ${name} { ${body} }${packed ? " packed" : ""};`;
}

/** "A=1, B=0x10" / one per line -> enum values. Invalid entries are dropped. */
export function parseEnumValues(text: string): EnumValue[] {
  const out: EnumValue[] = [];
  for (const part of text.split(/[,;\n]/)) {
    const [name, value] = part.split("=").map((s) => s.trim());
    if (!name) continue;
    const n = value === undefined || value === "" ? 0 : Number(value);
    if (!Number.isFinite(n)) continue;
    out.push({ name, value: n });
  }
  return out;
}

type TypesStore = {
  structs: StructDef[];
  enums: EnumDef[];
  /** Struct whose members the editor shows, and whose type format_at renders. */
  selected: string | null;
  selectedEnum: string | null;
  /** Address the live value column reads from, as typed. */
  addr: string;
  values: Record<string, FieldRead>;
  busy: boolean;
  error: string | null;
  /** Bumped by every catalog mutation: decompiled functions are stale. */
  invalidated: number;
  load: () => Promise<void>;
  select: (name: string | null) => void;
  selectEnum: (name: string | null) => void;
  setAddr: (text: string) => void;
  readValues: () => Promise<void>;
  createStruct: (name: string) => Promise<boolean>;
  deleteStruct: (name: string) => Promise<boolean>;
  addMember: (field: StructField) => Promise<boolean>;
  removeMember: (name: string) => Promise<boolean>;
  renameMember: (from: string, to: string) => Promise<boolean>;
  saveEnum: (def: EnumDef) => Promise<boolean>;
  deleteEnum: (name: string) => Promise<boolean>;
};

export const useTypes = create<TypesStore>((set, get) => {
  /** Run a catalog mutation, then re-read the catalog and the live values. */
  const mutate = async (fn: () => Promise<unknown>): Promise<boolean> => {
    set({ busy: true });
    try {
      await fn();
      set((s) => ({ busy: false, error: null, invalidated: s.invalidated + 1 }));
      await get().load();
      await get().readValues();
      return true;
    } catch (e) {
      set({ busy: false, error: errorText(e) });
      return false;
    }
  };

  const current = (): StructDef | undefined => get().structs.find((s) => s.name === get().selected);

  return {
    structs: [],
    enums: [],
    selected: null,
    selectedEnum: null,
    addr: "",
    values: {},
    busy: false,
    error: null,
    invalidated: 0,

    load: async () => {
      try {
        const [structs, enums] = await Promise.all([
          call<{ structs: StructDef[] }>("types", "list_structs"),
          call<{ enums: EnumDef[] }>("types", "list_enums"),
        ]);
        set((s) => {
          const list = structs.structs ?? [];
          const keep = list.some((x) => x.name === s.selected)
            ? s.selected
            : (list[0]?.name ?? null);
          const enumList = enums.enums ?? [];
          const keepEnum = enumList.some((x) => x.name === s.selectedEnum)
            ? s.selectedEnum
            : (enumList[0]?.name ?? null);
          return {
            structs: list,
            enums: enumList,
            selected: keep,
            selectedEnum: keepEnum,
            error: null,
          };
        });
      } catch (e) {
        set({ error: errorText(e) });
      }
    },

    select: (selected) => {
      set({ selected, values: {} });
      void get().readValues();
    },
    selectEnum: (selectedEnum) => set({ selectedEnum }),
    setAddr: (addr) => {
      set({ addr, values: {} });
      void get().readValues();
    },

    readValues: async () => {
      const { selected, addr, structs } = get();
      const def = structs.find((s) => s.name === selected);
      const base = parseAddress(addr);
      if (!def || base === null) {
        set({ values: {} });
        return;
      }
      const entries = await Promise.all(
        def.fields.map(async (f): Promise<[string, FieldRead]> => {
          try {
            const v = await call<FieldValue>("types", "read_field", {
              struct: def.name,
              field: f.name,
              addr: base,
            });
            return [f.name, v];
          } catch (e) {
            return [f.name, { error: errorText(e) }];
          }
        }),
      );
      // a newer address or struct selection wins over this reply
      if (get().addr !== addr || get().selected !== def.name) return;
      set({ values: Object.fromEntries(entries) });
    },

    createStruct: (name) =>
      mutate(() => call("types", "declare", { decl: `struct ${name} {};` })).then((ok) => {
        if (ok) set({ selected: name });
        return ok;
      }),

    deleteStruct: (name) =>
      mutate(() => call("types", "remove_struct", { name })).then((ok) => {
        if (ok && get().selected === name) set({ selected: null, values: {} });
        return ok;
      }),

    addMember: (field) => {
      const def = current();
      if (!def) return Promise.resolve(false);
      return mutate(() =>
        call("types", "add_member", {
          name: def.name,
          field: field.name,
          type: field.type,
          array_count: field.array_count,
        }),
      );
    },

    removeMember: (name) => {
      const def = current();
      if (!def) return Promise.resolve(false);
      const fields = def.fields.filter((f) => f.name !== name);
      return mutate(() => call("types", "declare", { decl: declOf(def.name, fields, def.packed) }));
    },

    renameMember: (from, to) => {
      const def = current();
      if (!def) return Promise.resolve(false);
      const fields = def.fields.map((f) => (f.name === from ? { ...f, name: to } : f));
      return mutate(() => call("types", "declare", { decl: declOf(def.name, fields, def.packed) }));
    },

    saveEnum: (def) =>
      mutate(() =>
        call("types", "create_enum", {
          name: def.name,
          underlying: def.underlying,
          values: def.values,
        }),
      ),

    deleteEnum: (name) =>
      mutate(() => call("types", "remove_enum", { name })).then((ok) => {
        if (ok && get().selectedEnum === name) set({ selectedEnum: null });
        return ok;
      }),
  };
});
