import { Reader, Writer } from "../buffer.js";

export const FileAccess = {
  FILE_READ_DATA: 0x00000001,
  FILE_WRITE_DATA: 0x00000002,
  FILE_APPEND_DATA: 0x00000004,
  FILE_READ_EA: 0x00000008,
  FILE_WRITE_EA: 0x00000010,
  FILE_EXECUTE: 0x00000020,
  FILE_DELETE_CHILD: 0x00000040,
  FILE_READ_ATTRIBUTES: 0x00000080,
  FILE_WRITE_ATTRIBUTES: 0x00000100,
  DELETE: 0x00010000,
  READ_CONTROL: 0x00020000,
  GENERIC_READ: 0x80000000,
  GENERIC_WRITE: 0x40000000,
  GENERIC_EXECUTE: 0x20000000,
  GENERIC_ALL: 0x10000000,
} as const;

export const ShareAccess = {
  READ: 0x00000001,
  WRITE: 0x00000002,
  DELETE: 0x00000004,
} as const;

export const CreateDisposition = {
  SUPERSEDE: 0,
  OPEN: 1,
  CREATE: 2,
  OPEN_IF: 3,
  OVERWRITE: 4,
  OVERWRITE_IF: 5,
} as const;

export const CreateOptions = {
  DIRECTORY_FILE: 0x00000001,
  WRITE_THROUGH: 0x00000002,
  SEQUENTIAL_ONLY: 0x00000004,
  NON_DIRECTORY_FILE: 0x00000040,
  DELETE_ON_CLOSE: 0x00001000,
} as const;

export const FileAttribute = {
  READONLY: 0x00000001,
  HIDDEN: 0x00000002,
  SYSTEM: 0x00000004,
  DIRECTORY: 0x00000010,
  ARCHIVE: 0x00000020,
  NORMAL: 0x00000080,
  TEMPORARY: 0x00000100,
  REPARSE_POINT: 0x00000400,
} as const;

export const IO_REPARSE_TAG_MOUNT_POINT = 0xa0000003;
export const IO_REPARSE_TAG_SYMLINK = 0xa000000c;

/**
 * Returns the reparse tag of an object, or `undefined` when it is not a
 * reparse point. A tag is NOT stored in the SMB2 attributes bitfield: it comes
 * from `Dirent.reparseTag` (directory listings). Pass a `Dirent`, or any
 * `{ attributes, reparseTag? }`. A bare attributes number can only say whether
 * the object is a reparse point, not which kind, so it yields `undefined`.
 */
export function reparseTagOf(
  x: { attributes: number; reparseTag?: number | undefined },
): number | undefined {
  if ((x.attributes & FileAttribute.REPARSE_POINT) === 0) return undefined;
  return x.reparseTag;
}

export interface CreateRequest {
  desiredAccess: number;
  shareAccess: number;
  createDisposition: number;
  createOptions: number;
  fileAttributes: number;
  filename: string; // forward-slash or backslash; we normalize to backslash, no leading slash
}

export function encodeCreateRequest(req: CreateRequest): Buffer {
  const name = req.filename.replace(/^[\\/]+/, "").replace(/\//g, "\\");
  const nameBuf = Buffer.from(name, "utf16le");
  const w = new Writer();
  w.u16(57); // StructureSize
  w.u8(0); // SecurityFlags (reserved)
  w.u8(0); // RequestedOplockLevel = NONE
  w.u32(2); // ImpersonationLevel = Impersonation
  w.u64(0n); // SmbCreateFlags
  w.u64(0n); // Reserved
  w.u32(req.desiredAccess >>> 0);
  w.u32(req.fileAttributes >>> 0);
  w.u32(req.shareAccess >>> 0);
  w.u32(req.createDisposition >>> 0);
  w.u32(req.createOptions >>> 0);
  // NameOffset (2) — at offset 44 from body start, so 64+56 from header start
  const nameOffset = 64 + 56;
  w.u16(nameOffset);
  w.u16(nameBuf.length);
  // CreateContextsOffset(4) + CreateContextsLength(4)
  w.u32(0);
  w.u32(0);
  // Buffer (filename) — must be at least 1 byte even if empty
  if (nameBuf.length === 0) w.u8(0);
  else w.bytes(nameBuf);
  return w.buffer();
}

export interface CreateResponse {
  oplockLevel: number;
  createAction: number;
  creationTime: bigint;
  lastAccessTime: bigint;
  lastWriteTime: bigint;
  changeTime: bigint;
  allocationSize: bigint;
  endOfFile: bigint;
  fileAttributes: number;
  fileId: Buffer; // 16 bytes
}

export function decodeCreateResponse(body: Buffer): CreateResponse {
  const r = new Reader(body);
  const ss = r.u16();
  if (ss !== 89) throw new Error(`CREATE resp StructureSize ${ss} != 89`);
  const oplockLevel = r.u8();
  r.u8(); // Flags (3.x); reserved on 2.x
  const createAction = r.u32();
  const creationTime = r.u64();
  const lastAccessTime = r.u64();
  const lastWriteTime = r.u64();
  const changeTime = r.u64();
  const allocationSize = r.u64();
  const endOfFile = r.u64();
  const fileAttributes = r.u32();
  r.u32(); // Reserved2
  const fileId = r.bytes(16);
  r.u32(); r.u32(); // CreateContextsOffset / Length (ignored)
  return {
    oplockLevel,
    createAction,
    creationTime,
    lastAccessTime,
    lastWriteTime,
    changeTime,
    allocationSize,
    endOfFile,
    fileAttributes,
    fileId,
  };
}
