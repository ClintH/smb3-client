# smb3-client: size and times in `readdir`

Goal: let `plugin-fs-smb` fill `internal.fs/entry` (`size`, `modifiedMs`, `createdMs`) from the directory listing itself, with no extra round trips. Part A is done in the **`ClintH/smb3-client` fork**. Part B is done afterwards in **fand**.

Background: see `plans/concepts-review.md` ("SMB listings have no size or times"). In short, SMB's `QUERY_DIRECTORY` already returns size and times for every entry, the fork parses them, and `Client.readdir(path, { withFileTypes: true })` throws them away.

## What the code looks like today (fork at `c4fce8b`, `/Users/af4766/repos/smb3-client`)

- `src/wire/structs/queryDirectory.ts`: `parseFileBothDirectoryInformation(buf)` returns `DirEntry[]`: `{ fileName, endOfFile: bigint, fileAttributes, creationTime: bigint, lastAccessTime: bigint, lastWriteTime: bigint, changeTime: bigint }` (raw FILETIME: 100 ns ticks since 1601). Already decoded; nothing to change in the wire layer.
- `src/open/readdir.ts`: `readdirAll(open, pattern)` pages `QUERY_DIRECTORY` (class `FileBothDirectoryInformation`) and returns `DirEntry[]`.
- `src/client.ts` (`readdir`, around line 169-193): for `{ withFileTypes: true }` it maps each `DirEntry` to `{ name, isFile, isDirectory } satisfies Dirent`. **This is where size and times are dropped.** The overloads are `readdir(path): Promise<string[]>` and `readdir(path, { withFileTypes: true }): Promise<Dirent[]>`.
- `src/types.ts`: `Dirent = { name; isFile(): boolean; isDirectory(): boolean }`. `FileStat` already has `size`, `ctime` (creation), `atime`, `mtime`, `changeTime`.
- `src/open/query.ts`: `metaToStat` converts the same raw fields with `smbTimeToDate` (`src/paths.ts`: `0n` returns `new Date(0)`, otherwise `Number(ft / 10000n - 11644473600000n)`). It throws `RangeError` when `endOfFile` exceeds `Number.MAX_SAFE_INTEGER`.
- `src/index.ts` exports `Dirent` as a type; the package exports only its entry point.
- Tooling: `npm run verify` = `typecheck` + `lint` (eslint) + `test` (`vitest run test/unit`). `test:integration` runs `test/integration`, gated by `test/helpers/integrationGate.ts`. **`dist/` is gitignored**: consumers get it from the `prepare` script (`tsc`) when they install the git dependency, so there is nothing to commit or rebuild by hand.

Existing tests to build on:

- `test/unit/wire/structs/queryDirectory.test.ts`: builds class-3 buffers by hand (`entry()` helper writing 94-byte prefix + name) and asserts `fileName` and `endOfFile`. It zeroes all the times, so the time fields are not currently asserted anywhere.
- `test/unit/open/readdir.test.ts`: a `dirEntry(name, isLast)` buffer helper (also zero times, hard-coded `endOfFile = 0`), `qdResp()`, `FakeTransport` (`test/helpers/fakeTransport.ts`), and a hand-built `Connection`/`Tree`/`Open`, used by the paging and Samba-continuation tests.
- `test/unit/client.readdir-shape.test.ts`: only asserts that `readdir` is a function. There is **no existing test of the `withFileTypes` mapping**, so the mapping needs to be made testable (A2).
- `test/unit/open/query.test.ts`: how `metaToStat` is tested; copy its style.
- `test/unit/paths.test.ts`: no test of `smbTimeToDate` at all.
- `test/integration/crud.test.ts`: `readdir` tests use the `string[]` form only.

## Part A: change in the fork

### A1. Extend `Dirent` (additive, non-breaking)

`src/types.ts`:

```ts
export interface Dirent {
  name: string;
  isFile: () => boolean;
  isDirectory: () => boolean;
  /** Size in bytes (`EndOfFile`). Servers usually report 0 for directories. Clamped to `Number.MAX_SAFE_INTEGER`. */
  size: number;
  /** Last write time. */
  mtime: Date;
  /** Creation time (same meaning as `FileStat.ctime`). A server that reports none yields `new Date(0)`. */
  ctime: Date;
}
```

Names match `FileStat` so a caller can treat a `Dirent` and a `FileStat` alike. Leave `atime` and `changeTime` out; nothing needs them. Check that no existing code constructs a `Dirent` literal (`grep -rn "Dirent" src test client_example`); the `satisfies Dirent` in `client.ts` is the only producer.

### A2. Make the mapping a pure function and use it

`src/open/readdir.ts` already owns `DirEntry` handling. Add next to `readdirAll`:

```ts
import { FileAttribute } from "../wire/structs/create.js";
import { smbTimeToDate } from "../paths.js";
import type { Dirent } from "../types.js";

/** Lists never throw for one oversized entry (unlike `metaToStat`): clamp instead. */
function endOfFileToNumber(eof: bigint): number {
  return eof > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(eof);
}

export function direntFromEntry(e: DirEntry): Dirent {
  const isDir = (e.fileAttributes & FileAttribute.DIRECTORY) !== 0;
  return {
    name: e.fileName,
    isFile: () => !isDir,
    isDirectory: () => isDir,
    size: endOfFileToNumber(e.endOfFile),
    mtime: smbTimeToDate(e.lastWriteTime),
    ctime: smbTimeToDate(e.creationTime),
  };
}
```

`src/client.ts`: replace the inline `entries.map(...)` body with `return entries.map(direntFromEntry);` and import it from `./open/readdir.js`. If `FileAttribute` and `Dirent` are no longer used elsewhere in `client.ts`, drop the unused imports (lint will say). Keep the `string[]` branch (`entries.map((e) => e.fileName)`) untouched.

Rules:

1. **Reuse `smbTimeToDate`**; do not add another FILETIME conversion.
2. **Do not throw for a huge size** (clamp, as above). Leave `metaToStat`/`stat` behaviour alone.
3. **Zero FILETIME stays `new Date(0)`** (existing `smbTimeToDate` behaviour, consistent with `stat`). It cannot be told apart from a real 1970 timestamp; document it and let consumers treat epoch 0 as unknown (fand does, Part B).
4. No change to `readdirAll`, paging, signing/encryption or the continuation-name workaround. No extra requests.

### A3. Tests (items 1-5 in `test/unit`, run by `npm test`; item 6 is integration)

1. **`test/unit/wire/structs/queryDirectory.test.ts`**: add a case to the class-3 test (or a new one) that writes non-zero `creationTime`, `lastWriteTime`, `changeTime`, `endOfFile` for two chained entries and asserts every field of the parsed `DirEntry`, so the time offsets are pinned down (today only names and EOF are asserted).
2. **`test/unit/open/readdir.test.ts`**: add a new `describe("direntFromEntry")`:
   - a file `DirEntry` (attributes `0x80`) gives `isFile() === true`, `isDirectory() === false`, `size` equal to the bigint as a number, `mtime`/`ctime` equal to the expected `Date`s;
   - a directory (`0x10`) gives `isDirectory() === true`;
   - `creationTime: 0n` gives `ctime.getTime() === 0`;
   - `endOfFile: 2n ** 60n` gives `size === Number.MAX_SAFE_INTEGER` and does not throw.
   Build the expected FILETIME in the test, e.g. `(BigInt(Date.UTC(2024, 0, 2, 3, 4, 5)) + 11644473600000n) * 10000n`.
3. **`test/unit/open/readdir.test.ts`**, optionally: extend the local `dirEntry()` helper with optional size/time arguments (default zeros, so existing tests are unaffected) and add one `readdirAll` test proving the values survive paging.
4. **`test/unit/paths.test.ts`**: add `smbTimeToDate` tests: `0n` returns epoch 0; `116444736000000000n` (1970-01-01 in FILETIME) returns epoch 0; the `Date.UTC(2024, ...)` value above round-trips.
5. **`test/unit/client.readdir-shape.test.ts`**: leave as is.
6. **`test/integration/crud.test.ts`** (runs only against a real share via `integrationGate`): add `readdir withFileTypes returns size and times`: write a file with known bytes, `readdir(base, { withFileTypes: true })`, find it, assert `size` equals the byte length, `mtime` is within a few seconds of now, and `ctime` is a valid `Date`. Follow the file's existing create/cleanup pattern.

### A4. Docs and example

- `README.md` (`readdir` section, around line 160): change "Pass `{ withFileTypes: true }` to get `Dirent` objects with `isFile()` and `isDirectory()` methods" to also list `size`, `mtime` and `ctime`, with the notes that directory sizes are usually 0 and that a zero creation time reads as the Unix epoch. Add a one-line mention that no extra requests are made.
- `client_example/05-list-directory.ts` (the `withFileTypes` loop): print `size` and `mtime` too.
- `docs/superpowers/specs/2026-05-09-node-smb3-client-design.md` (line ~335, the `Dirent` interface): update it to match, or leave if you treat that file as a frozen historical spec.
- `package.json` version: bump a minor if you tag releases; fand pins by SHA, so the version is cosmetic.

### A5. Verify, push, hand over the SHA

1. `npm run verify` (typecheck, lint, unit tests) must be green; `npm run test:integration` against a real share if you have one configured.
2. Prove the consumer path works: in a scratch directory, `npm install /Users/af4766/repos/smb3-client` (or the git URL after pushing) and check `node_modules/smb3-client/dist/types.d.ts` has `size`, `mtime` and `ctime` on `Dirent` (this exercises `prepare`).
3. Manually list one real folder on each server you use (Synology/Samba, macOS share, Windows) and compare `size`/`mtime`/`ctime` with Finder or `ls -l`. Differences that are not bugs: FAT/exFAT shares may report a zero creation time; some servers report 0 for directory sizes.
4. Commit and push to `ClintH/smb3-client`. **Give me the full commit SHA.**

## Part B: fand (after A is pushed)

Executed in this repo once you give me the SHA.

1. `packages/plugin-fs-smb/package.json`: change the pin to `github:ClintH/smb3-client#<new sha>`; update `pnpm-workspace.yaml` (`allowBuilds` key contains the old SHA) to the new one; `pnpm install`.
2. `packages/plugin-fs-smb/src/traversable-provider.ts` (children listing, currently `records: fsEntryRecords({ name: childName })`): pass `size` (files only), `modifiedMs: entry.mtime.getTime()` and `createdMs: entry.ctime.getTime()`. Treat a time of `0` (epoch) as unknown and leave the field out, so a FAT share does not show "1 Jan 1970".
3. Keep directories' `size` undefined (the lister already shows `--` for them, but the record should not claim a size).
4. Use the same millisecond values for the `revision` token of the child (currently `child:${childName}`), e.g. `mtime:${ms}:${size}`, so a changed file invalidates the cached listing. Check `docs/providers/cache.md` and the SMB tests for anything that asserts the old string.
5. Tests: extend the SMB provider children test with a fake client returning the new `Dirent` fields: file with size/mtime/ctime, directory (no size), zero creation time (no `createdMs`). Conformance (`createFakeFs...`-style) already requires a valid named record; keep that passing.
6. Docs: update `docs/providers` SMB notes and delete the "SMB listings have no size or times; blocked on `smb3-client`" item from `plans/concepts-review.md`.
7. Check: `pnpm run typecheck`, `pnpm run lint:fix`, then `pnpm exec vitest run` in `packages/plugin-fs-smb`.

## Out of scope

- `statBig()` / bigint sizes for listings. A clamp is enough for any real file.
- `atime` and `changeTime` on `Dirent`.
- Entry-record deferral by subscription intensity: unnecessary because the values arrive with the listing (see `plans/concepts-review.md`).
- Any change to paging, signing, encryption or the continuation-name workaround in `readdirAll`.

## Done when

- `client.readdir(p, { withFileTypes: true })` returns `size`, `mtime` and `ctime` with no additional requests, and the string form is unchanged.
- Unit tests cover the parser, the mapping, the zero-time case and the size clamp; `npm run verify` is green.
- fand lists an SMB folder in the GUI with Size and Modified columns filled for files.
