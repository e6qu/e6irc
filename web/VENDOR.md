# Web client dependencies & provenance

The web client is a Vite project. Its dependencies are pinned in
`package.json` and locked with integrity (SHA-512) hashes in
`pnpm-lock.yaml` — that lockfile is the provenance record; `node_modules`
and `dist` are build artifacts and are not committed.

Build:

```
cd web && pnpm install && pnpm build   # -> web/dist (content-hashed)
```

## Runtime dependencies (bundled into `dist`)

| Package         | Version | License | Source |
|-----------------|---------|---------|--------|
| htmx.org        | 2.0.10  | 0BSD    | https://github.com/bigskysoftware/htmx |
| htmx-ext-ws     | 2.0.4   | 0BSD    | https://github.com/bigskysoftware/htmx-extensions |

Build-only: `vite` 8.1.5 (MIT). All licenses are permissive and
compatible with e6irc's AGPL-3.0-or-later. Exact integrity hashes are in
`pnpm-lock.yaml`; update it (and this table) whenever a version changes.
