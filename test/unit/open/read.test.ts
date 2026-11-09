import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Open } from "../../../src/open/open.js";
import { Tree } from "../../../src/tree/tree.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { Writer } from "../../../src/wire/buffer.js";
import { Dialect, SmbCommand } from "../../../src/wire/commands.js";
import { readAll, readAt, readMany } from "../../../src/open/read.js";

function readResp(messageId: bigint, sessionId: bigint, treeId: number, payload: Buffer, grant = 1): Buffer {
  const w = new Writer();
  w.u16(17);
  const dataOffset = 64 + 16;
  w.u8(dataOffset); w.u8(0);
  w.u32(payload.length);
  w.u32(0); w.u32(0);
  w.bytes(payload);
  const hdr = encodeHeader({
    command: SmbCommand.READ, creditCharge: 1, creditRequestResponse: grant, flags: 0x1,
    messageId, sessionId, treeId, status: 0,
  });
  return Buffer.concat([hdr, w.buffer()]);
}

describe("readAll", () => {
  it("chunks reads above maxReadSize and concatenates results", async () => {
    const ft = new FakeTransport();
    let calls = 0;
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      if (smb.readUInt16LE(12) !== SmbCommand.READ) return;
      const messageId = smb.readBigUInt64LE(24);
      // body starts at offset 64; READ body fields: StructureSize(2) Padding(1) Reserved(1) Length(4) Offset(8)
      const length = smb.readUInt32LE(64 + 4);
      const offset = smb.readBigUInt64LE(64 + 8);
      const buf = Buffer.alloc(length);
      for (let i = 0; i < length; i++) buf[i] = (Number(offset & 0xffn) + i) & 0xff;
      calls++;
      ft.deliver(readResp(messageId, 0xabcdn, 0x42, buf));
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1, maxReadSize: 100 };
    const tree = Object.assign(Object.create(Tree.prototype), {
      conn,
      session: { sessionId: 0xabcdn, makeSigning: () => undefined },
      treeId: 0x42, shareType: "disk", path: "x", maximalAccess: 0,
    }) as Tree;
    const fid = Buffer.alloc(16, 0xfe);
    const open = new (Open as unknown as { new (...args: unknown[]): Open })(tree, fid, {} as never);
    const out = await readAll(open, 250n);
    expect(out.length).toBe(250);
    expect(calls).toBe(3); // 100 + 100 + 50
    // Verify byte pattern
    expect(out[0]).toBe(0);
    expect(out[100]).toBe(100);
    expect(out[200]).toBe(200);
  });
});

describe("readAt pipelining", () => {
  function setup(fileSize: number, maxRead: number, shortFirst = false) {
    const ft = new FakeTransport();
    let inflight = 0, peak = 0, short = shortFirst;
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      if (smb.readUInt16LE(12) !== SmbCommand.READ) return;
      const messageId = smb.readBigUInt64LE(24);
      let length = smb.readUInt32LE(64 + 4);
      const offset = Number(smb.readBigUInt64LE(64 + 8));
      inflight++; peak = Math.max(peak, inflight);
      if (short && length > 10) { length = 10; short = false; }
      length = Math.max(0, Math.min(length, fileSize - offset));
      const buf = Buffer.alloc(length);
      for (let i = 0; i < length; i++) buf[i] = (offset + i) & 0xff;
      setTimeout(() => {
        inflight--;
        if (length === 0) {
          const hdr = encodeHeader({ command: SmbCommand.READ, creditCharge: 1, creditRequestResponse: 64, flags: 0x1, messageId, sessionId: 0xabcdn, treeId: 0x42, status: 0xc0000011 });
          ft.deliver(Buffer.concat([hdr, Buffer.alloc(9)]));
        } else ft.deliver(readResp(messageId, 0xabcdn, 0x42, buf, 64));
      }, 1);
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1, maxReadSize: maxRead };
    const tree = Object.assign(Object.create(Tree.prototype), {
      conn, session: { sessionId: 0xabcdn, makeSigning: () => undefined },
      treeId: 0x42, shareType: "disk", path: "x", maximalAccess: 0,
    }) as Tree;
    const open = new (Open as unknown as { new (...args: unknown[]): Open })(tree, Buffer.alloc(16, 1), {} as never);
    return { open, peak: () => peak };
  }
  const expected = (o: number, n: number) => Buffer.from(Array.from({ length: n }, (_, i) => (o + i) & 0xff));

  it("keeps several READs in flight and preserves order", async () => {
    const { open, peak } = setup(1000, 100);
    const out = await readAt(open, 0n, 1000);
    expect(out.equals(expected(0, 1000))).toBe(true);
    expect(peak()).toBeGreaterThan(1);
  });

  it("stops at EOF and returns the short tail", async () => {
    const { open } = setup(250, 100);
    const out = await readAt(open, 0n, 1000);
    expect(out.equals(expected(0, 250))).toBe(true);
  });

  it("refills a mid-range short read without leaving a gap", async () => {
    const { open } = setup(500, 100, true);
    const out = await readAt(open, 0n, 500);
    expect(out.equals(expected(0, 500))).toBe(true);
  });

  it("readMany returns each range in order", async () => {
    const { open } = setup(1000, 100);
    const [a, b] = await readMany(open, [{ offset: 5n, length: 300 }, { offset: 900n, length: 300 }]);
    expect(a!.equals(expected(5, 300))).toBe(true);
    expect(b!.equals(expected(900, 100))).toBe(true);
  });
});
