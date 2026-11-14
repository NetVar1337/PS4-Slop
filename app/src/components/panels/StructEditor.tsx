// app/src/components/panels/StructEditor.tsx
// ReClass-style struct/enum editor over the engine `types` tool. The catalog
// lives in the engine (persisted per binary hash); this view is a thin client:
// left list of structs/enums, right member table with a live value column read
// at a user-supplied address. Every mutation bumps the catalog generation,
// which invalidates decompiled functions, so the hint below the table says so

import { useEffect, useState } from "react";
import { Braces, Pencil, Plus, RefreshCw, Save, Trash2 } from "lucide-react";
import IconButton from "@/components/IconButton";
import { parseAddress } from "@/lib/format";
import { parseEnumValues, useTypes } from "@/store/types";

const kPrimitiveTypes = [
  "u8",
  "u16",
  "u32",
  "u64",
  "i8",
  "i16",
  "i32",
  "i64",
  "f32",
  "f64",
  "ptr",
  "char",
];

export default function StructEditor() {
  const {
    structs,
    enums,
    selected,
    selectedEnum,
    addr,
    values,
    busy,
    error,
    invalidated,
    load,
    select,
    selectEnum,
    setAddr,
    readValues,
    createStruct,
    deleteStruct,
    addMember,
    removeMember,
    renameMember,
    saveEnum,
    deleteEnum,
  } = useTypes();

  const [newStruct, setNewStruct] = useState("");
  const [fieldType, setFieldType] = useState("u32");
  const [fieldName, setFieldName] = useState("");
  const [fieldCount, setFieldCount] = useState("0");
  const [renaming, setRenaming] = useState<string | null>(null);
  const [renameText, setRenameText] = useState("");
  const [enumName, setEnumName] = useState("");
  const [underlying, setUnderlying] = useState("u32");
  const [enumValues, setEnumValues] = useState("");

  useEffect(() => {
    void load();
  }, [load]);

  // the form always mirrors the selected enum so Save upserts what is shown
  useEffect(() => {
    const def = enums.find((e) => e.name === selectedEnum);
    setEnumName(def?.name ?? "");
    setUnderlying(def?.underlying ?? "u32");
    setEnumValues(def ? def.values.map((v) => `${v.name}=${v.value}`).join(", ") : "");
  }, [selectedEnum, enums]);

  const def = structs.find((s) => s.name === selected);
  const addrOk = parseAddress(addr) !== null;
  const typeNames = [
    ...kPrimitiveTypes,
    ...structs.map((s) => s.name),
    ...enums.map((e) => e.name),
  ];

  const submitField = async () => {
    if (fieldName.trim() === "") return;
    const ok = await addMember({
      name: fieldName.trim(),
      type: fieldType.trim() || "u8",
      offset: 0,
      size: 0,
      array_count: Math.max(0, Number(fieldCount) || 0),
    });
    if (ok) {
      setFieldName("");
      setFieldCount("0");
    }
  };

  const submitRename = async (from: string) => {
    const to = renameText.trim();
    setRenaming(null);
    if (to !== "" && to !== from) await renameMember(from, to);
  };

  return (
    <div className="types">
      <div className="types-list">
        <div className="view-bar" style={{ padding: "var(--pad-sm)" }}>
          <span className="panel-title">Types</span>
          <div className="spacer" />
          <IconButton tip="Reload catalog" onClick={() => void load()}>
            <RefreshCw size={13} />
          </IconButton>
        </div>
        <div className="panel-body">
          <div className="types-group">Structs</div>
          {structs.length === 0 && <div className="faint types-hint">no structs yet</div>}
          {structs.map((s) => (
            <button
              type="button"
              key={s.name}
              className="types-row"
              data-selected={s.name === selected}
              onClick={() => select(s.name)}
            >
              <Braces size={12} aria-hidden />
              <span className="fn-name">{s.name}</span>
              <span className="faint">{s.size}</span>
            </button>
          ))}
          <div className="types-create">
            <input
              className="addr-input"
              style={{ width: "100%" }}
              aria-label="New struct name"
              placeholder="New struct…"
              value={newStruct}
              onChange={(e) => setNewStruct(e.target.value)}
              onKeyDown={(e) => {
                if (e.key !== "Enter" || newStruct.trim() === "") return;
                void createStruct(newStruct.trim()).then((ok) => ok && setNewStruct(""));
              }}
            />
            <IconButton
              tip="Create struct"
              disabled={busy || newStruct.trim() === ""}
              onClick={() =>
                void createStruct(newStruct.trim()).then((ok) => ok && setNewStruct(""))
              }
            >
              <Plus size={13} />
            </IconButton>
          </div>

          <div className="types-group">Enums</div>
          {enums.length === 0 && <div className="faint types-hint">no enums yet</div>}
          {enums.map((e) => (
            <button
              type="button"
              key={e.name}
              className="types-row"
              data-selected={e.name === selectedEnum}
              onClick={() => selectEnum(e.name)}
            >
              <span className="fn-name">{e.name}</span>
              <span className="faint">{e.underlying}</span>
            </button>
          ))}
          <div className="types-create">
            <button
              type="button"
              className="row-action"
              onClick={() => selectEnum(null)}
              disabled={busy}
            >
              <Plus size={11} /> new enum
            </button>
          </div>
        </div>
      </div>

      <div className="stack">
        <div className="view-bar">
          <span className="panel-title">{def ? `struct ${def.name}` : "Struct editor"}</span>
          {def && (
            <IconButton
              tip={`Delete struct ${def.name}`}
              disabled={busy}
              onClick={() => void deleteStruct(def.name)}
            >
              <Trash2 size={13} />
            </IconButton>
          )}
          <div className="spacer" />
          <label className="view-label">
            addr
            <input
              className="addr-input mono"
              aria-label="Address for live values"
              placeholder="0x400000"
              value={addr}
              aria-invalid={!addrOk && addr !== ""}
              onChange={(e) => setAddr(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void readValues()}
            />
          </label>
          <IconButton tip="Re-read values" disabled={!addrOk} onClick={() => void readValues()}>
            <RefreshCw size={13} />
          </IconButton>
        </div>

        <div className="panel-body">
          {error !== null && (
            <div className="error-text" role="alert" style={{ padding: "var(--pad-sm)" }}>
              {error}
            </div>
          )}
          {def === undefined ? (
            <div className="faint types-hint">Select a struct, or create one on the left.</div>
          ) : (
            <>
              <table className="table types-table">
                <thead>
                  <tr>
                    <th>offset</th>
                    <th>size</th>
                    <th>type</th>
                    <th>name</th>
                    <th>value</th>
                    <th aria-label="actions" />
                  </tr>
                </thead>
                <tbody>
                  {def.fields.map((f) => {
                    const v = values[f.name];
                    return (
                      <tr key={f.name}>
                        <td className="mono">
                          {f.offset.toString(16).toUpperCase().padStart(3, "0")}
                        </td>
                        <td className="mono">{f.size}</td>
                        <td className="mono">{f.type}</td>
                        <td>
                          {renaming === f.name ? (
                            <input
                              className="addr-input mono"
                              aria-label={`Rename ${f.name}`}
                              autoFocus
                              value={renameText}
                              onChange={(e) => setRenameText(e.target.value)}
                              onBlur={() => void submitRename(f.name)}
                              onKeyDown={(e) => {
                                if (e.key === "Enter") void submitRename(f.name);
                                if (e.key === "Escape") setRenaming(null);
                              }}
                            />
                          ) : (
                            f.name
                          )}
                        </td>
                        <td className="mono">
                          {v === undefined ? (
                            <span className="faint">{addrOk ? "…" : "—"}</span>
                          ) : "error" in v ? (
                            <span className="faint">{v.error}</span>
                          ) : (
                            v.hex
                          )}
                        </td>
                        <td className="types-actions">
                          <IconButton
                            tip={`Rename member ${f.name}`}
                            disabled={busy}
                            onClick={() => {
                              setRenaming(f.name);
                              setRenameText(f.name);
                            }}
                          >
                            <Pencil size={12} />
                          </IconButton>
                          <IconButton
                            tip={`Remove member ${f.name}`}
                            disabled={busy}
                            onClick={() => void removeMember(f.name)}
                          >
                            <Trash2 size={12} />
                          </IconButton>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>

              <div className="types-create">
                <input
                  className="addr-input mono"
                  aria-label="Member type"
                  list="types-member-types"
                  placeholder="type"
                  value={fieldType}
                  onChange={(e) => setFieldType(e.target.value)}
                />
                <datalist id="types-member-types">
                  {typeNames.map((t) => (
                    <option key={t} value={t} />
                  ))}
                </datalist>
                <input
                  className="addr-input mono"
                  aria-label="Member name"
                  placeholder="name"
                  value={fieldName}
                  onChange={(e) => setFieldName(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && void submitField()}
                />
                <input
                  className="addr-input mono"
                  style={{ width: 56 }}
                  aria-label="Array count"
                  placeholder="count"
                  value={fieldCount}
                  onChange={(e) => setFieldCount(e.target.value)}
                />
                <button
                  type="button"
                  className="row-action"
                  disabled={busy || fieldName.trim() === ""}
                  onClick={() => void submitField()}
                >
                  <Plus size={11} /> add member
                </button>
              </div>

              {invalidated > 0 && (
                <div className="types-note" role="status">
                  decompiler cache invalidated ({invalidated} edit{invalidated === 1 ? "" : "s"}) ·
                  functions re-render on the next decompile
                </div>
              )}
            </>
          )}

          <div className="types-enum">
            <div className="types-group">Enum</div>
            <div className="types-create">
              <input
                className="addr-input mono"
                aria-label="Enum name"
                placeholder="name"
                value={enumName}
                onChange={(e) => setEnumName(e.target.value)}
              />
              <select
                className="select"
                aria-label="Enum underlying type"
                value={underlying}
                onChange={(e) => setUnderlying(e.target.value)}
              >
                {["u8", "u16", "u32", "u64", "i32"].map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
              <IconButton
                tip="Save enum"
                disabled={
                  busy || enumName.trim() === "" || parseEnumValues(enumValues).length === 0
                }
                onClick={() =>
                  void saveEnum({
                    name: enumName.trim(),
                    underlying,
                    values: parseEnumValues(enumValues),
                  })
                }
              >
                <Save size={13} />
              </IconButton>
              {selectedEnum !== null && (
                <IconButton
                  tip={`Delete enum ${selectedEnum}`}
                  disabled={busy}
                  onClick={() => void deleteEnum(selectedEnum)}
                >
                  <Trash2 size={13} />
                </IconButton>
              )}
            </div>
            <textarea
              className="types-enum-values mono"
              aria-label="Enum values"
              placeholder="NAME=1, OTHER=0x10"
              value={enumValues}
              onChange={(e) => setEnumValues(e.target.value)}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
