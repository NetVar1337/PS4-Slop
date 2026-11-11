#!/usr/bin/env python3
"""Regenerate THIRD_PARTY_NOTICES.md from the real dependency trees.

Sources (all local, no network):
  * _ext/<dep>-src        C/C++ deps fetched by cmake/deps.cmake (configure first)
  * app/node_modules      frontend packages (run `npm ci` in app/ first)
  * cargo metadata        Rust crates of app/src-tauri (registry must be cached)
  * tools/licenses/       license texts for bundled binaries without a local copy

Usage:  python tools/gen_third_party_notices.py [--check]
--check exits 1 when the committed file differs from what would be generated.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXT = ROOT / "_ext"
APP = ROOT / "app"
OUT = ROOT / "THIRD_PARTY_NOTICES.md"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
MAGICMIDA_VERSION = (ROOT / "tools" / "magicmida-version.txt").read_text(encoding="utf-8").split()[0]

# C/C++ dependencies fetched by cmake/deps.cmake. `files` are paths inside
# _ext/<dir>-src whose full text is reproduced; `extract` pulls a comment block
# out of a header for projects that ship their notice only in source.
NATIVE = [
    dict(name="fmt", version="11.1.4", url="https://github.com/fmtlib/fmt", spdx="MIT",
         dir="fmt", files=["LICENSE"], used="engine, tests (via spdlog/hyperion)"),
    dict(name="spdlog", version="1.15.3", url="https://github.com/gabime/spdlog", spdx="MIT",
         dir="spdlog", files=["LICENSE"], used="engine (hyperion logging)"),
    dict(name="Capstone", version="5.0.6", url="https://github.com/capstone-engine/capstone",
         spdx="BSD-3-Clause AND NCSA", dir="capstone", files=["LICENSE.TXT", "LICENSE_LLVM.TXT"],
         used="engine (ARM/ARM64 decoding)"),
    dict(name="zlib", version="1.3.1", url="https://github.com/madler/zlib", spdx="Zlib",
         dir="zlib_kr", files=["LICENSE"], used="engine"),
    dict(name="FreeType", version="2.13.3", url="https://gitlab.freedesktop.org/freetype/freetype",
         spdx="FTL (chosen from FTL OR GPL-2.0-or-later)", dir="freetype",
         files=["LICENSE.TXT", "docs/FTL.TXT"], used="legacy ImGui shell (reverse-slop.exe)",
         note="Portions of this software are copyright (c) 2024 The FreeType Project "
              "(www.freetype.org). All rights reserved."),
    dict(name="JSON for Modern C++ (nlohmann/json)", version="3.12.0", url="https://github.com/nlohmann/json",
         spdx="MIT", dir="nlohmann_json", files=["LICENSE.MIT"], used="engine, tests"),
    dict(name="Zydis", version="4.1.1", url="https://github.com/zyantific/zydis", spdx="MIT",
         dir="zydis", files=["LICENSE"], used="engine (x86/x64 decoder + encoder)"),
    dict(name="Zycore", version="(Zydis 4.1.1 submodule)", url="https://github.com/zyantific/zycore-c",
         spdx="MIT", dir="zydis", files=["dependencies/zycore/LICENSE"], used="engine (via Zydis)"),
    dict(name="Dear ImGui", version="1.92.1-docking", url="https://github.com/ocornut/imgui", spdx="MIT",
         dir="imgui", files=["LICENSE.txt"], used="legacy ImGui shell"),
    dict(name="cpp-httplib", version="0.18.7", url="https://github.com/yhirose/cpp-httplib", spdx="MIT",
         dir="httplib", files=["LICENSE"], used="engine (MCP/HTTP server, web tool)"),
    dict(name="Unicorn Engine", version="2.1.4", url="https://github.com/unicorn-engine/unicorn",
         spdx="GPL-2.0-only (parts LGPL-2.1-or-later)", dir="unicorn", files=["COPYING", "COPYING.LGPL2"],
         used="engine (emulator, statically linked)",
         note="Unicorn is licensed under the GNU GPL version 2. Because reverse-slop-engine.exe "
              "statically links Unicorn, the distributed engine binary as a whole is subject to "
              "GPL-2.0 terms: the complete corresponding source is this repository plus the Unicorn "
              "2.1.4 release archive pinned (with SHA-256) in cmake/deps.cmake. reverse-slop's own "
              "source remains MIT-licensed, which is GPL-2.0 compatible."),
    dict(name="SQLite", version="3.50.4", url="https://www.sqlite.org", spdx="blessing (public domain)",
         dir="sqlite", extract=("sqlite3.h", r"/\*\n(\*\* 2001-09-15.*?)\*{10,}"), used="engine (session store)"),
    dict(name="Lua", version="5.4.7", url="https://www.lua.org", spdx="MIT", dir="lua",
         extract=("src/lua.h", r"/\*{10,}\n(\* Copyright \(C\).*?)\*{10,}/"), used="engine (scripting)"),
]

# Code or data vendored into this repository (not fetched at build time).
VENDORED = [
    dict(name="Hyperion", path="src/hyperion",
         url="https://github.com/Sidenai/hyperion-disassembler",
         text="Vendored analysis/decompiler engine (`hype` namespace), modified for reverse-slop. "
              "The upstream repository declares no license; copyright remains with its authors. "
              "Redistribution of this directory relies on the upstream authors' permission."),
    dict(name="PS4 NID symbol names", path="src/hyperion/data/ps4_nid_names.inc",
         url="https://github.com/idc/ps4libdoc (branch doc, commit 8bff4863ac2f788149bbbf13a7eddc1222aec08b)",
         text="Derived from known_names.txt in ps4libdoc. The upstream repository declares no "
              "license; the file is a list of public PS4 SDK symbol identifiers used to resolve NID "
              "hashes. Copyright its respective contributors. Users can add or override names in "
              "`%LOCALAPPDATA%\\reverse-slop\\nids.txt` (one `name` or `NID name` per line)."),
    dict(name="ps4debug-NG wire protocol", path="src/core/runtime/ps4_protocol.hpp",
         url="https://github.com/Pharaoh2k/ps4debug-NG",
         text="Protocol constants and packet layouts re-implemented from ps4debug-NG's "
              "debugger/include/protocol.h. No upstream code is copied; the upstream repository "
              "declares no license."),
    dict(name="reverse-slap (fork origin)", path="(repository history)",
         url="https://github.com/kaizer1308/reverse-slap",
         text="reverse-slop is a fork of reverse-slap. The upstream repository declares no license; "
              "code inherited from it remains copyright its authors."),
]

# Separately downloaded executables shipped inside the installer/portable dist.
BUNDLED = [
    dict(name="Magicmida", version=MAGICMIDA_VERSION, url="https://github.com/Hendi48/Magicmida",
         spdx="GPL-3.0", license="tools/licenses/GPL-3.0.txt",
         text="Shipped unmodified as separate executables under engine/tools/magicmida "
              "(mere aggregation). Corresponding source: the tagged release "
              f"https://github.com/Hendi48/Magicmida/releases/tag/{MAGICMIDA_VERSION}."),
    dict(name="ScyllaHide (inside the Magicmida x64 package)", version="as packaged by Magicmida",
         url="https://github.com/x64dbg/ScyllaHide", spdx="GPL-3.0", license="tools/licenses/GPL-3.0.txt",
         text="Shipped unmodified inside the Magicmida x64 package. Corresponding source: "
              "https://github.com/x64dbg/ScyllaHide."),
]

LICENSE_FILE_RE = re.compile(r"^(licen[cs]e|copying|notice|copyright|unlicense)([-._].*)?$", re.I)


def read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").strip()


def native_texts(dep: dict) -> list[tuple[str, str]]:
    src = EXT / f"{dep['dir']}-src"
    if not src.is_dir():
        sys.exit(f"missing {src}: configure the CMake build first")
    out = []
    for rel in dep.get("files", []):
        p = src / rel
        if not p.is_file():
            sys.exit(f"missing license file {p}")
        out.append((rel, read_text(p)))
    if "extract" in dep:
        rel, pattern = dep["extract"]
        m = re.search(pattern, read_text(src / rel), re.S)
        if not m:
            sys.exit(f"license block not found in {src / rel}")
        block = "\n".join(re.sub(r"^\s*\*{1,2} ?", "", line) for line in m.group(1).splitlines())
        out.append((rel, block.strip()))
    return out


def license_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.iterdir() if p.is_file() and LICENSE_FILE_RE.match(p.name))


def npm_packages() -> list[dict]:
    lock = json.loads((APP / "package-lock.json").read_text(encoding="utf-8"))
    pkgs = []
    for path, info in lock.get("packages", {}).items():
        if not path.startswith("node_modules/") or info.get("dev") or info.get("devOptional"):
            continue
        name = path.rsplit("node_modules/", 1)[1]
        d = APP / path
        if not d.is_dir():
            sys.exit(f"missing {d}: run `npm ci` in app/ first")
        meta = json.loads((d / "package.json").read_text(encoding="utf-8"))
        lic = info.get("license") or meta.get("license") or "UNKNOWN"
        if isinstance(lic, dict):
            lic = lic.get("type", "UNKNOWN")
        repo = meta.get("repository")
        if isinstance(repo, dict):
            repo = repo.get("url")
        pkgs.append(dict(name=name, version=info.get("version", meta.get("version", "")),
                         license=lic, url=repo or meta.get("homepage") or f"https://www.npmjs.com/package/{name}",
                         files=license_files(d)))
    return sorted(pkgs, key=lambda p: (p["name"], p["version"]))


def cargo_crates() -> list[dict]:
    r = subprocess.run(["cargo", "metadata", "--format-version", "1", "--locked", "--offline",
                        "--filter-platform", "x86_64-pc-windows-msvc"],
                       cwd=APP / "src-tauri", capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        sys.exit(f"cargo metadata failed (fetch the crates once with `cargo fetch`):\n{r.stderr}")
    meta = json.loads(r.stdout)
    by_id = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    root = meta["resolve"]["root"]
    # normal (shipped) dependency closure; build-only deps never reach the binary
    seen, stack = set(), [root]
    while stack:
        cur = stack.pop()
        for dep in nodes[cur]["deps"]:
            if any(k["kind"] is None for k in dep["dep_kinds"]) and dep["pkg"] not in seen:
                seen.add(dep["pkg"])
                stack.append(dep["pkg"])
    crates = []
    for pid in seen:
        p = by_id[pid]
        d = Path(p["manifest_path"]).parent
        files = license_files(d)
        if p.get("license_file"):
            lf = d / p["license_file"]
            if lf.is_file() and lf not in files:
                files.append(lf)
        crates.append(dict(name=p["name"], version=p["version"], license=p.get("license") or "see license file",
                           url=p.get("repository") or f"https://crates.io/crates/{p['name']}", files=files))
    return sorted(crates, key=lambda c: (c["name"], c["version"]))


def grouped_texts(items: list[dict]) -> list[tuple[str, list[str]]]:
    """Dedupe identical license texts, keep the packages each one covers."""
    groups: dict[str, list[str]] = {}
    for it in items:
        for f in it["files"]:
            groups.setdefault(read_text(f), []).append(f"{it['name']} {it['version']}")
    return sorted(((t, sorted(set(n))) for t, n in groups.items()), key=lambda g: g[1][0].lower())


def fence(text: str) -> str:
    ticks = "````" if "```" in text else "```"
    return f"{ticks}text\n{text}\n{ticks}\n"


def md_cell(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def generate() -> str:
    o: list[str] = []
    w = o.append
    w("# Third-party notices\n")
    w(f"reverse-slop {VERSION} is MIT-licensed (see `LICENSE`, copyright (c) 2026 NetVar1337). "
      "It builds on, links, bundles or derives from the components below; each keeps its own "
      "license. This file is generated by `tools/gen_third_party_notices.py` and ships next to "
      "the application in the installer and the portable build.\n")

    w("## Native dependencies (fetched by `cmake/deps.cmake`, SHA-256 pinned)\n")
    w("| Component | Version | License | Used by | Source |\n|---|---|---|---|---|")
    for d in NATIVE:
        w(f"| {md_cell(d['name'])} | {md_cell(d['version'])} | {md_cell(d['spdx'])} | {md_cell(d['used'])} | {d['url']} |")
    w("")
    w("## Vendored code and data\n")
    for v in VENDORED:
        w(f"### {v['name']}\n\n- Location: `{v['path']}`\n- Origin: {v['url']}\n\n{v['text']}\n")
    w("## Bundled third-party executables\n")
    for b in BUNDLED:
        w(f"### {b['name']} ({b['version']})\n\n- License: {b['spdx']} (full text in the appendix)\n"
          f"- Source: {b['url']}\n\n{b['text']}\n")
    w("Windows installers may also embed or download the Microsoft Edge WebView2 runtime "
      "bootstrapper, redistributed under the Microsoft WebView2 distribution terms.\n")

    npm = npm_packages()
    w("## Frontend packages bundled into the UI (`app/package-lock.json`, runtime only)\n")
    w("| Package | Version | License | Source |\n|---|---|---|---|")
    for p in npm:
        w(f"| {md_cell(p['name'])} | {p['version']} | {md_cell(p['license'])} | {md_cell(p['url'])} |")
    w("")
    crates = cargo_crates()
    w("## Rust crates linked into the UI host (`app/src-tauri/Cargo.lock`, Windows, normal deps)\n")
    w("| Crate | Version | License | Source |\n|---|---|---|---|")
    for c in crates:
        w(f"| {md_cell(c['name'])} | {c['version']} | {md_cell(c['license'])} | {md_cell(c['url'])} |")
    w("")

    w("---\n\n# License texts\n")
    w("## Native dependencies\n")
    for d in NATIVE:
        w(f"### {d['name']} {d['version']}\n")
        if d.get("note"):
            w(d["note"] + "\n")
        for rel, text in native_texts(d):
            w(f"`{rel}`:\n")
            w(fence(text))
    w("## Bundled executables\n")
    done = set()
    for b in BUNDLED:
        if b["license"] in done:
            w(f"### {b['name']}\n\nSame {b['spdx']} text as above.\n")
            continue
        done.add(b["license"])
        w(f"### {b['name']}\n")
        w(fence(read_text(ROOT / b["license"])))
    for title, items in (("Frontend packages", npm), ("Rust crates", crates)):
        w(f"## {title}\n")
        missing = [f"{i['name']} {i['version']} ({i['license']})" for i in items if not i["files"]]
        if missing:
            w("Packages that ship no separate license file (license per their SPDX id and "
              "source headers): " + ", ".join(missing) + ".\n")
        for text, names in grouped_texts(items):
            w("Applies to: " + ", ".join(names) + "\n")
            w(fence(text))
    return "\n".join(o).rstrip() + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="fail when THIRD_PARTY_NOTICES.md is stale")
    args = ap.parse_args()
    text = generate()
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print("THIRD_PARTY_NOTICES.md is stale: run python tools/gen_third_party_notices.py", file=sys.stderr)
            return 1
        print("THIRD_PARTY_NOTICES.md is up to date")
        return 0
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(text) // 1024} KiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
