# Contributing

Thank you for helping improve `filecage`.

## Ground rules

- Security behavior must fail closed by default.
- Do not add runtime dependencies. Keep development dependencies limited to fast-check for property fuzz tests.
- Keep Node 18 compatibility.
- Keep ESM, generated CommonJS, and hand-written TypeScript definitions in sync.
- Do not trust filenames, browser MIME types, or user-controlled metadata as
  proof of content.
- Do not weaken a rejection merely because a file is common. Make dangerous
  behavior explicit policy opt-in and document the risk.

## Development setup

The published library has no runtime dependencies. Run `npm ci` before `npm run test:fuzz` because fast-check is a development-only dependency.

```sh
npm test
node scripts/build-cjs.mjs --check
node scripts/cli-smoke.mjs
npm pack --dry-run
```

## Required checks for every change

1. Add regression tests before changing security behavior.
2. Run the full test suite.
3. Regenerate `cjs/index.cjs` with `node scripts/build-cjs.mjs` when
   `src/index.mjs` changes.
4. Update `types/index.d.ts` when the public API changes.
5. Update README finding codes, policy tables, and threat-model notes when
   behavior changes.
6. Verify that no fixture contains real secrets, personal data, or malicious
   live infrastructure references.

## Test style

Core tests use `node:test` and `node:assert/strict`. Property fuzz tests also use fast-check. Byte fixtures should be as
small as possible while preserving the structure under test. Prefer tables of
explicit attack cases over broad snapshots. Tests for malformed parsers must
prove termination and bounds checking, not merely output shape.

## Scope

Good contributions include additional real-world magic-byte formats, stronger
polyglot detection, sharper parser bounds, clearer findings, framework-free
integration examples, and platform compatibility tests.

Out of scope additions include malware scanning engines, network fetching,
native image decoders, archive extraction, and dependencies that execute or
render uploaded content.
