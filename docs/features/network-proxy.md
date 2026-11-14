# Host network and proxy

Both features act on the **analysis PC**, not the console.

## Raw capture

Raw-socket capture (SIO_RCVALL, administrator rights) with:

- packet paging with text filters, DNS log and statistics;
- stream listing and reassembly;
- per-packet HTTP/TLS/DNS inspection;
- PCAP export.

```json
{ "tool": "network", "action": "capture_start", "params": { "filter": "tcp port 443" } }
{ "tool": "network", "action": "packets", "params": { "limit": 100 } }
{ "tool": "network", "action": "streams", "params": {} }
{ "tool": "network", "action": "export_pcap", "params": { "path": "C:/tmp/cap.pcap" } }
```

`network.status`, `capture_stop`, `dns`, `stats`, `stream_data`, `reassemble_stream`,
`connections` and `deep_inspect` complete the surface.

## Localhost inspection proxy

An independent HTTP/1.1 proxy on loopback: start/stop, captured exchanges, replay.

```json
{ "tool": "proxy", "action": "start", "params": { "port": 8080 } }
{ "tool": "proxy", "action": "entries", "params": { "limit": 50 } }
{ "tool": "proxy", "action": "replay", "params": { "id": 1 } }
```

CONNECT tunnels record metadata and SNI only. TLS interception (`mitm_enable`) requires
explicit consent, installs a local CA, and is fully reversible (`mitm_uninstall`).

## Outbound HTTP

The `web` tool does WinHTTP GET/POST without inheriting browser cookies. Private and
loopback targets are denied unless `web_allow_private` is on (and then only what
`web_allowlist` allows).
