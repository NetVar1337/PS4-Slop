#!/usr/bin/env node
// tools/gen_help_index.mjs — build the in-app help search index from docs/**/*.md.
//
//   node tools/gen_help_index.mjs                       JSON on stdout
//   node tools/gen_help_index.mjs --out <path>          write a file instead
//   node tools/gen_help_index.mjs --base /SlopStation/  prefix every url (Pages sub-path)
//
// Output contract: docs/help-index.md. Entries follow SUMMARY.md order, anchors follow
// mdBook's slug rules so `url` opens the right heading on the built site.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..");
const SRC = path.join(repo, "docs");
const EXCERPT = 240;

const args = process.argv.slice(2);
const opt = (name, fallback = null) => {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : fallback;
};
const OUT = opt("--out");
const BASE = opt("--base", "");

// mdBook's anchor rule: keep letters/digits/_/-/space, drop everything else, lowercase,
// spaces to '-', then de-duplicate with -1, -2, ... per page.
function slug(text, seen) {
  let s = text
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .trim()
    .replace(/\s+/g, "-");
  if (s === "") s = "section";
  const n = seen.get(s) ?? 0;
  seen.set(s, n + 1);
  return n === 0 ? s : `${s}-${n}`;
}

// markdown -> the text a reader sees: drop code fences, images, link targets and emphasis
function plain(md) {
  return md
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/!\[[^\]]*\]\([^)]*\)/g, " ")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/<[^>]+>/g, " ")
    .replace(/[`*_>#|]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function summaryOrder() {
  const file = path.join(SRC, "SUMMARY.md");
  if (!fs.existsSync(file)) return [];
  return [...fs.readFileSync(file, "utf8").matchAll(/\]\(([^)]+\.md)\)/g)].map((m) => m[1]);
}

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === "book" || e.name.startsWith(".")) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.name.endsWith(".md") && e.name !== "SUMMARY.md") out.push(p);
  }
  return out;
}

const rel = (p) => path.relative(SRC, p).split(path.sep).join("/");

// SUMMARY order first, then anything not listed (so a new page is never silently lost)
const listed = summaryOrder();
const files = [
  ...listed.map((r) => path.join(SRC, r)).filter((p) => fs.existsSync(p)),
  ...walk(SRC).filter((p) => !listed.includes(rel(p))),
];

const entries = [];
for (const file of files) {
  const text = fs.readFileSync(file, "utf8");
  const page = rel(file).replace(/\.md$/, "");
  const seen = new Map();
  // split on ATX headings, keeping the heading line with its body
  const parts = text.split(/^(#{1,6})[ \t]+(.+)$/gm);
  let headings = 0;
  for (let i = 1; i < parts.length; i += 3) {
    const heading = parts[i + 1].replace(/\s*#+\s*$/, "").trim();
    const body = parts[i + 2] ?? "";
    headings++;
    const anchor = slug(heading, seen);
    entries.push({
      title: heading,
      anchor,
      section: heading,
      text: plain(body).slice(0, EXCERPT),
      url: `${BASE}${page}.html#${anchor}`,
      path: rel(file),
    });
  }
  if (headings === 0) {
    console.error(`no heading in ${rel(file)}`);
    process.exitCode = 1;
  }
}

if (entries.length === 0) {
  console.error("no entries: docs/ has no markdown headings");
  process.exit(1);
}

const index = {
  generated: new Date().toISOString(),
  source: "docs",
  count: entries.length,
  entries,
};
const json = JSON.stringify(index, null, 2) + "\n";

if (OUT) {
  fs.mkdirSync(path.dirname(path.resolve(OUT)), { recursive: true });
  fs.writeFileSync(OUT, json);
  console.error(`help index: ${entries.length} entries, ${files.length} pages -> ${OUT}`);
} else {
  process.stdout.write(json);
}
