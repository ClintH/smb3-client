import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Tree } from "../../../src/tree/tree.js";
import { Open } from "../../../src/open/open.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { Writer } from "../../../src/wire/buffer.js";
import { Dialect, SmbCommand } from "../../../src/wire/commands.js";
import { CreateDisposition, CreateOptions, FileAccess } from "../../../src/wire/structs/create.js";

function makeCreateRespFrame(messageId: bigint, sessionId: bigint, treeId: number, fid: Buffer, eof: bigint): Buffer {
  const w = new Writer();
  w.u16(89); w.u8(0); w.u8(0); w.u32(2);
  w.u64(0n); w.u64(0n); w.u64(0n); w.u64(0n);
  w.u64(0n); w.u64(eof); w.u32(0x80); w.u32(0);
  w.bytes(fid); w.u32(0); w.u32(0);
  const hdr = encodeHeader({
    command: SmbCommand.CREATE,
    creditCharge: 1, creditRequestResponse: 1, flags: 0x1,
    messageId, sessionId, treeId, status: 0,
  });
  return Buffer.concat([hdr, w.buffer()]);
}

function makeCloseRespFrame(messageId: bigint, sessionId: bigint, treeId: number, status = 0): Buffer {
  const w = new Writer();
  w.u16(60); w.u16(0); w.u32(0);
  w.u64(0n); w.u64(0n); w.u64(0n); w.u64(0n);
  w.u64(0n); w.u64(0n); w.u32(0);
  const hdr = encodeHeader({
    command: SmbCommand.CLOSE,
    creditCharge: 1, creditRequestResponse: 1, flags: 0x1,
    messageId, sessionId, treeId, status,
  });
  return Buffer.concat([hdr, w.buffer()]);
}

describe("Open / withOpen", () => {
  it("CREATEs and CLOSEs the handle even on error", async () => {
    const ft = new FakeTransport();
    const fid = Buffer.alloc(16, 0xfe);
    let opens = 0, closes = 0;
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      const messageId = smb.readBigUInt64LE(24);
      const cmd = smb.readUInt16LE(12);
      if (cmd === SmbCommand.CREATE) {
        opens++;
        ft.deliver(makeCreateRespFrame(messageId, 0xabcdn, 0x42, fid, 100n));
      } else if (cmd === SmbCommand.CLOSE) {
        closes++;
        ft.deliver(makeCloseRespFrame(messageId, 0xabcdn, 0x42));
      }
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const fakeSess = { sessionId: 0xabcdn, signingKey: Buffer.alloc(16), makeSigning: () => undefined } as never;
    const tree = Object.assign(Object.create(Tree.prototype), {
      conn, session: fakeSess, treeId: 0x42, shareType: "disk", path: "\\\\srv\\share", maximalAccess: 0,
    }) as Tree;

    let threw = false;
    try {
      await Open.withOpen(tree, {
        filename: "x.txt",
        desiredAccess: FileAccess.FILE_READ_DATA | FileAccess.FILE_READ_ATTRIBUTES,
        shareAccess: 7,
        createDisposition: CreateDisposition.OPEN,
        createOptions: CreateOptions.NON_DIRECTORY_FILE,
      }, async () => { throw new Error("boom"); });
    } catch { threw = true; }
    expect(threw).toBe(true);
    expect(opens).toBe(1);
    expect(closes).toBe(1);
  });

  const STATUS_DIRECTORY_NOT_EMPTY = 0xc0000101;

  function treeWithCloseStatus(closeStatus: number): Tree {
    const ft = new FakeTransport();
    const fid = Buffer.alloc(16, 0xfe);
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      const messageId = smb.readBigUInt64LE(24);
      const cmd = smb.readUInt16LE(12);
      if (cmd === SmbCommand.CREATE)
        ft.deliver(makeCreateRespFrame(messageId, 0xabcdn, 0x42, fid, 100n));
      else if (cmd === SmbCommand.CLOSE)
        ft.deliver(makeCloseRespFrame(messageId, 0xabcdn, 0x42, closeStatus));
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const fakeSess = { sessionId: 0xabcdn, signingKey: Buffer.alloc(16), makeSigning: () => undefined } as never;
    return Object.assign(Object.create(Tree.prototype), {
      conn, session: fakeSess, treeId: 0x42, shareType: "disk", path: "\\\\srv\\share", maximalAccess: 0,
    }) as Tree;
  }

  const deleteOnClose = {
    filename: "dir",
    desiredAccess: FileAccess.DELETE,
    shareAccess: 7,
    createDisposition: CreateDisposition.OPEN,
    createOptions: CreateOptions.DIRECTORY_FILE | CreateOptions.DELETE_ON_CLOSE,
  };

  it("surfaces a CLOSE failure when the callback succeeded (DELETE_ON_CLOSE outcome)", async () => {
    const tree = treeWithCloseStatus(STATUS_DIRECTORY_NOT_EMPTY);
    await expect(Open.withOpen(tree, deleteOnClose, async () => "ok")).rejects.toThrow(/CLOSE failed/);
  });

  it("keeps the callback's error when CLOSE also fails", async () => {
    const tree = treeWithCloseStatus(STATUS_DIRECTORY_NOT_EMPTY);
    await expect(Open.withOpen(tree, deleteOnClose, async () => { throw new Error("primary"); })).rejects.toThrow("primary");
  });
});
