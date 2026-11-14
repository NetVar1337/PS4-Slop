# Persistence, filesystem and web

## Persistence

SQLite under the app data directory:

- session snapshots (`save`, `list`, `load`, `delete`) and key/value storage
  (`kv_set`, `kv_get`);
- Hyperion `.hdb` export/import (`hype_save`, `hype_load`), so an analyzed image can be
  reopened without re-running the analysis.

```json
{ "tool": "persist", "action": "kv_set", "params": { "key": "project", "value": "demo" } }
{ "tool": "persist", "action": "list", "params": {} }
```

Renames, comments, bookmarks and declared types also persist — per file hash, so they
remap across bases and survive restarts.

## Filesystem

Host filesystem access for the agent: `read_file`, `write_file`, `list_directory`,
`create_directory`, `delete_path`, `search_files`, `grep_in_files`.

The engine's own data directory is refused, so an agent cannot corrupt the session database
or the token store through `fs`.

## Web

`web.fetch` and `web.post` are outbound WinHTTP calls that do not inherit browser cookies.
Private/loopback targets are denied unless `web_allow_private` is set, and `web_allowlist`
narrows what is reachable when it is.

```json
{ "tool": "web", "action": "fetch", "params": { "url": "https://example.com/" } }
```
