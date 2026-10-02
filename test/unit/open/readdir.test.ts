import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Open } from "../../../src/open/open.js";
import { Tree } from "../../../src/tree/tree.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { Writer } from "../../../src/wire/buffer.js";
import { Dialect, SmbCommand, NTStatus } from "../../../src/wire/commands.js";
import { readdirAll, direntFromEntry } from "../../../src/open/readdir.js";
import type { DirEntry } from "../../../src/wire/structs/queryDirectory.js";

// FileBothDirectoryInformation (class 3): 94-byte fixed prefix + FileName.
// (The FileId* variant, class 37, appends Reserved2(2)+FileId(8) = 104 bytes.)
function dirEntry(
  name: string,
  isLast: boolean,
  extra: { size?: bigint; created?: bigint; written?: bigint } = {},
): Buffer {
  const nameBuf = Buffer.from(name, "utf16le");
  const recSize = 94 + nameBuf.length;
  const padded = (recSize + 7) & ~7;
  const w = new Writer();
  w.u32(isLast ? 0 : padded);
  w.u32(0);
  w.u64(extra.created ?? 0n); w.u64(0n); w.u64(extra.written ?? 0n); w.u64(0n);
  w.u64(extra.size ?? 0n); w.u64(0n); w.u32(0x80);
  w.u32(nameBuf.length); w.u32(0); w.u8(0); w.u8(0);
  w.bytes(Buffer.alloc(24)); w.bytes(nameBuf);
  w.pad(padded - recSize);
  return w.buffer();
}

function qdResp(messageId: bigint, status: number, payload: Buffer): Buffer {
  const w = new Writer();
  w.u16(9); w.u16(64 + 8); w.u32(payload.length);
  w.bytes(payload);
  const hdr = encodeHeader({
    command: SmbCommand.QUERY_DIRECTORY, creditCharge: 1, creditRequestResponse: 1, flags: 0x1,
    messageId, sessionId: 0xabcdn, treeId: 0x42, status,
  });
  return Buffer.concat([hdr, w.buffer()]);
}

describe("readdirAll", () => {
  it("repeats QUERY_DIRECTORY until STATUS_NO_MORE_FILES", async () => {
    const ft = new FakeTransport();
    let call = 0;
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      if (smb.readUInt16LE(12) !== SmbCommand.QUERY_DIRECTORY) return;
      const messageId = smb.readBigUInt64LE(24);
      call++;
      if (call === 1) {
        ft.deliver(qdResp(messageId, 0, Buffer.concat([dirEntry("a.txt", false), dirEntry("b.txt", true)])));
      } else if (call === 2) {
        ft.deliver(qdResp(messageId, 0, dirEntry("c.txt", true)));
      } else {
        ft.deliver(qdResp(messageId, NTStatus.STATUS_NO_MORE_FILES, Buffer.alloc(0)));
      }
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const tree = Object.assign(Object.create(Tree.prototype), {
      conn, session: { sessionId: 0xabcdn, makeSigning: () => undefined },
      treeId: 0x42, shareType: "disk", path: "x", maximalAccess: 0,
    }) as Tree;
    const open = new (Open as unknown as { new (...a: unknown[]): Open })(tree, Buffer.alloc(16, 0xfe), {} as never);
    const items = await readdirAll(open);
    expect(items.map((x) => x.fileName)).toEqual(["a.txt", "b.txt", "c.txt"]);
  });

  it("retries with the search pattern when an empty continuation is rejected (Samba/Synology)", async () => {
    const ft = new FakeTransport();
    // FileNameLength (utf16le bytes) of each QUERY_DIRECTORY request we send.
    const patternLens: number[] = [];
    let call = 0;
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      if (smb.readUInt16LE(12) !== SmbCommand.QUERY_DIRECTORY) return;
      const messageId = smb.readBigUInt64LE(24);
      patternLens.push(smb.readUInt16LE(64 + 26)); // body FileNameLength
      call++;
      if (call === 1) {
        // First page returns entries.
        ft.deliver(qdResp(messageId, 0, Buffer.concat([dirEntry("a.txt", false), dirEntry("b.txt", true)])));
      } else if (call === 2) {
        // Continuation with empty FileName — Samba/Synology rejects it.
        ft.deliver(qdResp(messageId, NTStatus.STATUS_OBJECT_NAME_INVALID, Buffer.alloc(0)));
      } else {
        // Retried continuation (pattern resent) succeeds and terminates.
        ft.deliver(qdResp(messageId, NTStatus.STATUS_NO_MORE_FILES, Buffer.alloc(0)));
      }
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const tree = Object.assign(Object.create(Tree.prototype), {
      conn, session: { sessionId: 0xabcdn, makeSigning: () => undefined },
      treeId: 0x42, shareType: "disk", path: "x", maximalAccess: 0,
    }) as Tree;
    const open = new (Open as unknown as { new (...a: unknown[]): Open })(tree, Buffer.alloc(16, 0xfe), {} as never);
    const items = await readdirAll(open);
    expect(items.map((x) => x.fileName)).toEqual(["a.txt", "b.txt"]);
    // first call sends "*" (2 bytes); the empty continuation (0) is rejected;
    // the retry resends "*" (2 bytes).
    expect(patternLens).toEqual([2, 0, 2]);
  });

  it("keeps size and times across pages", async () => {
    const ft = new FakeTransport();
    let call = 0;
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      if (smb.readUInt16LE(12) !== SmbCommand.QUERY_DIRECTORY) return;
      const messageId = smb.readBigUInt64LE(24);
      call++;
      if (call === 1) {
        ft.deliver(qdResp(messageId, 0, dirEntry("a.txt", true, { size: 11n, created: 5n, written: 7n })));
      } else if (call === 2) {
        ft.deliver(qdResp(messageId, 0, dirEntry("b.txt", true, { size: 22n, created: 6n, written: 8n })));
      } else {
        ft.deliver(qdResp(messageId, NTStatus.STATUS_NO_MORE_FILES, Buffer.alloc(0)));
      }
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const tree = Object.assign(Object.create(Tree.prototype), {
      conn, session: { sessionId: 0xabcdn, makeSigning: () => undefined },
      treeId: 0x42, shareType: "disk", path: "x", maximalAccess: 0,
    }) as Tree;
    const open = new (Open as unknown as { new (...a: unknown[]): Open })(tree, Buffer.alloc(16, 0xfe), {} as never);
    const items = await readdirAll(open);
    expect(items.map((x) => [x.fileName, x.endOfFile, x.creationTime, x.lastWriteTime])).toEqual([
      ["a.txt", 11n, 5n, 7n],
      ["b.txt", 22n, 6n, 8n],
    ]);
  });
});

const toFiletime = (ms: number): bigint => (BigInt(ms) + 11644473600000n) * 10000n;

function entryOf(over: Partial<DirEntry>): DirEntry {
  return {
    fileName: "f", endOfFile: 0n, fileAttributes: 0x80,
    creationTime: 0n, lastAccessTime: 0n, lastWriteTime: 0n, changeTime: 0n,
    ...over,
  };
}

describe("direntFromEntry", () => {
  const created = Date.UTC(2023, 5, 7, 8, 9, 10);
  const written = Date.UTC(2024, 0, 2, 3, 4, 5);

  it("maps a file entry", () => {
    const d = direntFromEntry(entryOf({
      fileName: "a.txt", endOfFile: 1234n,
      creationTime: toFiletime(created), lastWriteTime: toFiletime(written),
    }));
    expect(d.name).toBe("a.txt");
    expect(d.isFile()).toBe(true);
    expect(d.isDirectory()).toBe(false);
    expect(d.size).toBe(1234);
    expect(d.mtime).toEqual(new Date(written));
    expect(d.ctime).toEqual(new Date(created));
  });

  it("maps a directory entry", () => {
    const d = direntFromEntry(entryOf({ fileAttributes: 0x10 }));
    expect(d.isDirectory()).toBe(true);
    expect(d.isFile()).toBe(false);
  });

  it("maps a zero creation time to epoch 0", () => {
    expect(direntFromEntry(entryOf({ creationTime: 0n })).ctime.getTime()).toBe(0);
  });

  it("clamps an oversized EndOfFile instead of throwing", () => {
    const d = direntFromEntry(entryOf({ endOfFile: 2n ** 60n }));
    expect(d.size).toBe(Number.MAX_SAFE_INTEGER);
  });
});
