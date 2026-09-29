import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Open } from "../../../src/open/open.js";
import { Tree } from "../../../src/tree/tree.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { Writer } from "../../../src/wire/buffer.js";
import { Dialect, SmbCommand, NTStatus } from "../../../src/wire/commands.js";
import { readdirAll } from "../../../src/open/readdir.js";

// FileBothDirectoryInformation (class 3): 94-byte fixed prefix + FileName.
// (The FileId* variant, class 37, appends Reserved2(2)+FileId(8) = 104 bytes.)
function dirEntry(name: string, isLast: boolean): Buffer {
  const nameBuf = Buffer.from(name, "utf16le");
  const recSize = 94 + nameBuf.length;
  const padded = (recSize + 7) & ~7;
  const w = new Writer();
  w.u32(isLast ? 0 : padded);
  w.u32(0);
  w.u64(0n); w.u64(0n); w.u64(0n); w.u64(0n);
  w.u64(0n); w.u64(0n); w.u32(0x80);
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
});
