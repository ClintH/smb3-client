import { describe, it, expect } from "vitest";
import {
  encodeQueryDirectoryRequest,
  decodeQueryDirectoryResponse,
  parseFileIdBothDirectoryInformation,
  parseFileBothDirectoryInformation,
} from "../../../../src/wire/structs/queryDirectory.js";
import { Writer } from "../../../../src/wire/buffer.js";

describe("QUERY_DIRECTORY", () => {
  it("encodes structure size 33 and search pattern", () => {
    const fid = Buffer.alloc(16, 0xa1);
    const buf = encodeQueryDirectoryRequest({
      fileInformationClass: 37,
      flags: 0,
      fileIndex: 0,
      fileId: fid,
      searchPattern: "*",
      outputBufferLength: 65536,
    });
    expect(buf.readUInt16LE(0)).toBe(33);
    const off = buf.readUInt16LE(24);
    const len = buf.readUInt16LE(26);
    expect(buf.subarray(off - 64, off - 64 + len).toString("utf16le")).toBe("*");
  });

  it("parses FileIdBothDirectoryInformation entries", () => {
    // Build two entries
    const w = new Writer();
    function entry(name: string, isLast: boolean) {
      const nameBuf = Buffer.from(name, "utf16le");
      const recSize = 104 + nameBuf.length; // fixed header + name
      const padded = (recSize + 7) & ~7;
      w.u32(isLast ? 0 : padded);
      w.u32(0);
      w.u64(0n); w.u64(0n); w.u64(0n); w.u64(0n);
      w.u64(123n); // EOF
      w.u64(0n);
      w.u32(0x80); // attrs
      w.u32(nameBuf.length); // FileNameLength
      w.u32(0); // EaSize
      w.u8(0); w.u8(0); // ShortNameLength + Reserved
      w.bytes(Buffer.alloc(24)); // ShortName
      w.u16(0); // Reserved2
      w.bytes(Buffer.alloc(8)); // FileId
      w.bytes(nameBuf);
      const written = recSize;
      w.pad(padded - written);
    }
    entry("a.txt", false);
    entry("b.txt", true);
    const items = parseFileIdBothDirectoryInformation(w.buffer());
    expect(items.map((x) => x.fileName)).toEqual(["a.txt", "b.txt"]);
    expect(items[0]!.endOfFile).toBe(123n);
  });

  it("parses FileBothDirectoryInformation entries (class 3, no FileId trailer)", () => {
    const w = new Writer();
    function entry(name: string, isLast: boolean) {
      const nameBuf = Buffer.from(name, "utf16le");
      const recSize = 94 + nameBuf.length; // fixed header (no Reserved2+FileId) + name
      const padded = (recSize + 7) & ~7;
      w.u32(isLast ? 0 : padded);
      w.u32(0);
      w.u64(0n); w.u64(0n); w.u64(0n); w.u64(0n);
      w.u64(456n); // EOF
      w.u64(0n);
      w.u32(0x80); // attrs
      w.u32(nameBuf.length); // FileNameLength
      w.u32(0); // EaSize
      w.u8(0); w.u8(0); // ShortNameLength + Reserved1
      w.bytes(Buffer.alloc(24)); // ShortName
      w.bytes(nameBuf);
      w.pad(padded - recSize);
    }
    entry("x.txt", false);
    entry("y.txt", true);
    const items = parseFileBothDirectoryInformation(w.buffer());
    expect(items.map((x) => x.fileName)).toEqual(["x.txt", "y.txt"]);
    expect(items[0]!.endOfFile).toBe(456n);
  });

  it("decodeQueryDirectoryResponse returns the embedded buffer", () => {
    const inner = Buffer.from("0011223344", "hex");
    const w = new Writer();
    w.u16(9);
    w.u16(64 + 8);
    w.u32(inner.length);
    w.bytes(inner);
    expect(decodeQueryDirectoryResponse(w.buffer(), 64)).toEqual(inner);
  });
});
