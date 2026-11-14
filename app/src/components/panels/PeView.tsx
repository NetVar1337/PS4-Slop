// app/src/components/panels/PeView.tsx
// Image browser: ELF/SELF/PE/Mach-O sections, imports and exports. Port of
// src/ui/view_pe.cpp

import { useEffect, useState } from "react";
import Tabs, { panelId, tabId } from "@/components/Tabs";
import { useT } from "@/i18n";
import { formatLabel } from "@/lib/format";
import { showInDisassembly } from "@/lib/navigate";
import { hex, useDisasm } from "@/store/disasm";
import { usePe } from "@/store/pe";

type Sub = "sections" | "imports" | "exports";

export default function PeView() {
  const t = useT();
  const { pe, loading, error, load } = usePe();
  const image = useDisasm((s) => s.image);
  const [sub, setSub] = useState<Sub>("sections");

  useEffect(() => {
    void load();
  }, [load, image.name, image.path]);

  const base = pe.image_base ?? image.base ?? 0;
  const format = image.format ?? pe.format;
  const arch = image.arch ?? pe.arch;
  const isPe = format === "pe" || (format === undefined && pe.pe32plus !== undefined);
  const isElf = format === "elf" || format === "self";
  const importGroup = isElf ? "library" : isPe ? "DLL" : "dylib";

  const counts: Record<Sub, number> = {
    sections: pe.sections.length,
    imports: pe.imports.length,
    exports: pe.exports.length,
  };

  return (
    <div className="stack">
      <div className="view-bar">
        <Tabs<Sub>
          items={(["sections", "imports", "exports"] as const).map((s) => ({
            id: s,
            label: (
              <>
                {t(`pe.${s}`)}
                <span className="faint">{counts[s]}</span>
              </>
            ),
          }))}
          active={sub}
          onChange={setSub}
          label={t("pe.metadata")}
          idPrefix="image"
        />
        <div className="spacer" />
        <span className="faint mono" style={{ fontSize: 11 }}>
          {t("pe.meta", {
            format: formatLabel(format, isPe ? pe.pe32plus : undefined),
            arch: arch !== undefined ? t("pe.metaArch", { arch }) : "",
            base: hex(base),
            entry: hex(image.entry_va ?? base + (pe.entry_rva ?? 0)),
          })}
        </span>
      </div>

      <div
        className="panel-body swap-fade"
        key={sub}
        role="tabpanel"
        id={panelId("image", sub)}
        aria-labelledby={tabId("image", sub)}
      >
        {error !== null && (
          <div className="empty-hint error-text" role="alert" style={{ padding: "var(--pad-md)" }}>
            {error}
          </div>
        )}
        {loading && (
          <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
            {t("pe.reading")}
          </div>
        )}

        {sub === "sections" && (
          <table className="table">
            <caption className="sr-only">
              {t("pe.sectionsCaption", { format: formatLabel(format) })}
            </caption>
            <thead>
              <tr>
                <th scope="col" style={{ width: 90 }}>
                  {t("pe.name")}
                </th>
                <th scope="col" style={{ width: 130 }}>
                  {t("pe.va")}
                </th>
                <th scope="col" style={{ width: 90 }}>
                  {t("pe.rva")}
                </th>
                <th scope="col" style={{ width: 90 }}>
                  {t("pe.virtual")}
                </th>
                <th scope="col" style={{ width: 90 }}>
                  {t("pe.raw")}
                </th>
                <th scope="col">{t("pe.flags")}</th>
              </tr>
            </thead>
            <tbody>
              {pe.sections.map((s) => (
                <tr key={`${s.name}-${s.rva}`}>
                  <th scope="row" className="mono table-rowhead">
                    {s.name}
                  </th>
                  <td>
                    <button
                      type="button"
                      className="mono link"
                      onClick={() => showInDisassembly(base + s.rva)}
                    >
                      {hex(base + s.rva)}
                    </button>
                  </td>
                  <td className="mono faint">0x{s.rva.toString(16).toUpperCase()}</td>
                  <td className="mono faint">0x{s.vsize.toString(16).toUpperCase()}</td>
                  <td className="mono faint">0x{s.raw_size.toString(16).toUpperCase()}</td>
                  <td>
                    {s.exec && <span className="pill">{t("pe.exec")}</span>}{" "}
                    {s.writable && <span className="pill">{t("pe.write")}</span>}{" "}
                    {(isPe || isElf) && s.characteristics !== 0 && (
                      <span className="faint mono" style={{ fontSize: 11 }}>
                        0x{s.characteristics.toString(16).toUpperCase()}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {sub === "imports" && (
          <div>
            {pe.imports.map((d) => (
              <details key={d.dll} className="tree">
                <summary>
                  <span className="mono">
                    {d.dll === "" ? (isPe ? t("pe.unnamed") : t("pe.dynamic")) : d.dll}
                  </span>
                  <span className="faint">{d.functions.length}</span>
                </summary>
                <ul
                  className="plain-list"
                  aria-label={t("pe.importsFrom", { group: d.dll || importGroup })}
                >
                  {d.functions.map((fn, i) => (
                    <li className="tree-leaf mono" key={`${d.dll}-${i}`}>
                      {fn}
                    </li>
                  ))}
                </ul>
              </details>
            ))}
            {pe.imports.length === 0 && !loading && (
              <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>
                {t("pe.noImports")}
              </div>
            )}
          </div>
        )}

        {sub === "exports" && (
          <table className="table">
            <caption className="sr-only">
              {t("pe.exportsCaption", { format: formatLabel(format) })}
            </caption>
            <thead>
              <tr>
                {isPe && (
                  <th scope="col" style={{ width: 70 }}>
                    {t("pe.ordinal")}
                  </th>
                )}
                <th scope="col" style={{ width: 130 }}>
                  {t("pe.va")}
                </th>
                <th scope="col">{t("pe.name")}</th>
              </tr>
            </thead>
            <tbody>
              {pe.exports.map((e, i) => (
                <tr key={`${e.name}-${i}`}>
                  {isPe && <td className="mono faint">{e.ordinal}</td>}
                  <td>
                    <button
                      type="button"
                      className="mono link"
                      onClick={() => showInDisassembly(base + e.rva)}
                    >
                      {hex(base + e.rva)}
                    </button>
                  </td>
                  <td className="mono">{e.name}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
