# In-app help index

`tools/gen_help_index.mjs` turns this documentation into a flat JSON index that the app can
search from the command palette. It is generated, never edited by hand, and it is not
committed — a UI slice consumes it.

## Generate

```powershell
node tools/gen_help_index.mjs                       # JSON on stdout
node tools/gen_help_index.mjs --out app/public/help-index.json
node tools/gen_help_index.mjs --base /SlopStation/ --out help-index.json
```

Exit code 0 means the index was written; 1 means a documentation file could not be read
or no section was found (so CI fails instead of shipping an empty index).

## Output contract

```json
{
  "generated": "2026-11-14T09:00:00.000Z",
  "source": "docs",
  "count": 412,
  "entries": [
    {
      "title": "Live memory",
      "anchor": "live-memory",
      "section": "Live memory",
      "text": "The memory tool works on the console session and on a local Windows process alike. Read/write in hex, UTF-8, integer and float formats; ...",
      "url": "features/live-memory.html#live-memory",
      "path": "features/live-memory.md"
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `generated` | ISO timestamp of the run |
| `source` | always `docs` (the mdBook `src`) |
| `count` | number of entries |
| `entries[].title` | the page title for a level-1 heading, otherwise the heading text |
| `entries[].anchor` | mdBook-compatible anchor of that heading (`#` fragment without `#`) |
| `entries[].section` | the heading text as written |
| `entries[].text` | plain-text excerpt of the section, markdown stripped, whitespace collapsed, ~240 characters |
| `entries[].url` | site-relative URL: `<page>.html#<anchor>` (prefix with `--base` for a sub-path deploy) |
| `entries[].path` | source file relative to `docs/` |

Entries are emitted in `SUMMARY.md` order, so search results follow the book's reading
order. `SUMMARY.md` itself is not indexed.

## Notes for the consuming UI

- The index is static: rebuild it when the docs change (the `docs` workflow does).
- The Tauri app consumes it: `npm run help:index` (in `app/`) writes
  `src/generated/help-index.json`, which the command palette loads lazily for its **Help**
  results. `predev`/`prebuild` run it, so a fresh checkout needs no extra step.
- Anchors are generated the way mdBook generates them (lowercase, punctuation dropped,
  spaces to `-`, `-1`, `-2`… for duplicates). If a heading is renamed, the anchor changes —
  treat `url` as opaque.
- The excerpt is plain text, not HTML: render it as text, do not inject it.
