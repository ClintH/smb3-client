import { Reader, Writer } from "../buffer.js";

export interface QueryDirectoryRequest {
  fileInformationClass: number; // 3 = FileBothDirectoryInformation, 37 = FileIdBothDirectoryInformation
  flags: number; // RESTART_SCANS=1, RETURN_SINGLE_ENTRY=2, INDEX_SPECIFIED=4, REOPEN=0x10
  fileIndex: number;
  fileId: Buffer;
  searchPattern: string;
  outputBufferLength: number;
}

export const QueryDirectoryFlag = {
  RESTART_SCANS: 0x01,
  RETURN_SINGLE_ENTRY: 0x02,
  INDEX_SPECIFIED: 0x04,
  REOPEN: 0x10,
} as const;

export function encodeQueryDirectoryRequest(req: QueryDirectoryRequest): Buffer {
  const pat = Buffer.from(req.searchPattern, "utf16le");
  const w = new Writer();
  w.u16(33);
  w.u8(req.fileInformationClass);
  w.u8(req.flags);
  w.u32(req.fileIndex);
  w.bytes(req.fileId);
  w.u16(64 + 32); // FileNameOffset
  w.u16(pat.length);
  w.u32(req.outputBufferLength);
  if (pat.length === 0) w.u8(0);
  else w.bytes(pat);
  return w.buffer();
}

export function decodeQueryDirectoryResponse(body: Buffer, bodyAt = 64): Buffer {
  const r = new Reader(body);
  const ss = r.u16();
  if (ss !== 9) throw new Error(`QUERY_DIRECTORY resp StructureSize ${ss} != 9`);
  const offset = r.u16();
  const length = r.u32();
  const start = offset - bodyAt;
  return Buffer.from(body.subarray(start, start + length));
}

export interface DirEntry {
  fileName: string;
  endOfFile: bigint;
  fileAttributes: number;
  creationTime: bigint;
  lastAccessTime: bigint;
  lastWriteTime: bigint;
  changeTime: bigint;
}

export function parseFileIdBothDirectoryInformation(buf: Buffer): DirEntry[] {
  const out: DirEntry[] = [];
  let off = 0;
  while (off < buf.length) {
    const r = new Reader(buf);
    r.offset = off;
    const next = r.u32();
    r.u32(); // FileIndex
    const creationTime = r.u64();
    const lastAccessTime = r.u64();
    const lastWriteTime = r.u64();
    const changeTime = r.u64();
    const endOfFile = r.u64();
    r.u64(); // AllocationSize
    const fileAttributes = r.u32();
    const fileNameLength = r.u32();
    r.u32(); // EaSize
    r.u8(); // ShortNameLength
    r.u8(); // Reserved1
    r.bytes(24); // ShortName
    r.u16(); // Reserved2
    r.bytes(8); // FileId
    const fileName = fileNameLength > 0 ? r.utf16(fileNameLength) : "";
    out.push({ fileName, endOfFile, fileAttributes, creationTime, lastAccessTime, lastWriteTime, changeTime });
    if (next === 0) break;
    off += next;
  }
  return out;
}

/**
 * Parse a FileBothDirectoryInformation (class 3) buffer.
 *
 * Identical wire layout to {@link parseFileIdBothDirectoryInformation} except it
 * omits the trailing `Reserved2` (2 bytes) and `FileId` (8 bytes) that the
 * FileId* variant (class 37) appends after `ShortName`.
 *
 * Needed because macOS smbd rejects class 37 for QUERY_DIRECTORY with
 * STATUS_NO_SUCH_FILE, whereas class 3 is honored by macOS, Windows, and Samba.
 */
export function parseFileBothDirectoryInformation(buf: Buffer): DirEntry[] {
  const out: DirEntry[] = [];
  let off = 0;
  while (off < buf.length) {
    const r = new Reader(buf);
    r.offset = off;
    const next = r.u32();
    r.u32(); // FileIndex
    const creationTime = r.u64();
    const lastAccessTime = r.u64();
    const lastWriteTime = r.u64();
    const changeTime = r.u64();
    const endOfFile = r.u64();
    r.u64(); // AllocationSize
    const fileAttributes = r.u32();
    const fileNameLength = r.u32();
    r.u32(); // EaSize
    r.u8(); // ShortNameLength
    r.u8(); // Reserved1
    r.bytes(24); // ShortName
    const fileName = fileNameLength > 0 ? r.utf16(fileNameLength) : "";
    out.push({ fileName, endOfFile, fileAttributes, creationTime, lastAccessTime, lastWriteTime, changeTime });
    if (next === 0) break;
    off += next;
  }
  return out;
}
