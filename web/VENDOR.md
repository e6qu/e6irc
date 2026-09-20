# Web client dependencies & provenance

The web client is a Vite project. `package.json` names `vite` and `playwright`
at exact versions and `@axe-core/playwright` as the range `^4.12.1`. What pins
all three, and every transitive package, is `pnpm-lock.yaml`: it records one
exact version each (`@axe-core/playwright` 4.12.1) with an integrity (SHA-512)
hash, and CI, the container build, and the release build all install with
`--frozen-lockfile`, which fails rather than resolve anything the lockfile does
not name. That lockfile is the provenance record; `node_modules` and `dist` are
build artifacts and are not committed.

Build:

```
cd web && pnpm install --frozen-lockfile && pnpm build   # -> web/dist (content-hashed)
```

The production bundle has no runtime package dependencies; the chat client is
implemented with browser DOM and WebSocket APIs.

Build-only: `vite` 8.1.5 (MIT). Test-only: `playwright` 1.61.1
(Apache-2.0, published 2026-06-23) and `@axe-core/playwright` 4.12.1
(MPL-2.0). Playwright drives real browser journeys; axe checks their rendered
semantic structure. Neither is in the production bundle or container. Rust
HTTP clients cannot verify browser cookies, redirects, focus, or rendering.
All licenses are compatible with AGPL-3.0-or-later. Exact integrity hashes are
in `pnpm-lock.yaml`.
