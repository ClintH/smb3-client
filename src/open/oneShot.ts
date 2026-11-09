import type { Tree } from "../tree/tree.js";
import { compoundOpen, expectSuccess, type CompoundOp, type Response } from "./compound.js";
import { Open } from "./open.js";
import { readAt, readChunkSizeFor } from "./read.js";
import { writeAll } from "./write.js";
import { metaToStat } from "./query.js";
import { CreateDisposition, CreateOptions, FileAccess, ShareAccess, type CreateRequest, type CreateResponse } from "../wire/structs/create.js";
import { encodeReadRequest, decodeReadResponse } from "../wire/structs/read.js";
import { encodeWriteRequest, decodeWriteResponse } from "../wire/structs/write.js";
import { encodeSetInfoRequest, encodeFileRenameInformation, encodeFileDispositionInformation } from "../wire/structs/setInfo.js";
import { InfoType, FileInformationClass } from "../wire/structs/queryInfo.js";
import { NTStatus, SmbCommand } from "../wire/commands.js";
import { creditChargeFor } from "../connection/connection.js";
import type { FileStat } from "../types.js";

/** Whole-path operations that cost one round trip (CREATE + work + CLOSE compounded) instead of three. */

const SHARE_ALL = ShareAccess.READ | ShareAccess.WRITE | ShareAccess.DELETE;

const request = (filename: string, desiredAccess: number, createDisposition: number, createOptions: number): CreateRequest => ({
  filename, desiredAccess, shareAccess: SHARE_ALL, createDisposition, createOptions, fileAttributes: 0,
});

const setInfo = (fileId: Buffer, fileInformationClass: number, buffer: Buffer): CompoundOp => ({
  command: SmbCommand.SET_INFO,
  body: encodeSetInfoRequest({ infoType: InfoType.FILE, fileInformationClass, fileId, buffer }),
});

export function statPath(tree: Tree, filename: string): Promise<FileStat> {
  return compoundOpen(tree, request(filename, FileAccess.FILE_READ_ATTRIBUTES, CreateDisposition.OPEN, 0),
    () => [], (meta) => metaToStat(meta));
}

export function mkdirPath(tree: Tree, filename: string): Promise<void> {
  return compoundOpen(tree,
    request(filename, FileAccess.FILE_READ_ATTRIBUTES | FileAccess.FILE_WRITE_ATTRIBUTES, CreateDisposition.CREATE, CreateOptions.DIRECTORY_FILE),
    () => [], () => undefined);
}

/** Deletes via SET_INFO FileDispositionInformation, whose response reports failures synchronously. */
export function deletePathCompound(tree: Tree, filename: string, kind: number): Promise<void> {
  return compoundOpen(tree, request(filename, FileAccess.DELETE, CreateDisposition.OPEN, kind),
    (fileId) => [setInfo(fileId, FileInformationClass.FileDispositionInformation, encodeFileDispositionInformation(true))],
    (_meta, [resp]) => expectSuccess(resp!, "SET_INFO delete"));
}

export function renamePath(tree: Tree, from: string, to: string): Promise<void> {
  return compoundOpen(tree, request(from, FileAccess.DELETE | FileAccess.FILE_READ_ATTRIBUTES, CreateDisposition.OPEN, 0),
    (fileId) => [setInfo(fileId, FileInformationClass.FileRenameInformation,
      encodeFileRenameInformation({ replaceIfExists: false, fileName: to }))],
    (_meta, [resp]) => expectSuccess(resp!, "SET_INFO rename"));
}

/** Decodes a READ response taken from a compound; END_OF_FILE means no bytes. */
function readBytes(resp: Response): Buffer {
  if (resp.header.status === NTStatus.STATUS_END_OF_FILE) return Buffer.alloc(0);
  expectSuccess(resp, "READ");
  return decodeReadResponse(resp.body, 64);
}

const readOp = (offset: bigint, length: number) => (fileId: Buffer): CompoundOp[] => [{
  command: SmbCommand.READ,
  body: encodeReadRequest({ fileId, offset, length }),
  creditCharge: creditChargeFor(length),
}];

/** Whole file. The first chunk rides in the compound; the rest, if any, is read through a second open. */
export async function readFilePath(tree: Tree, filename: string): Promise<Buffer> {
  const chunk = readChunkSizeFor(tree.conn);
  const req = request(filename, FileAccess.FILE_READ_DATA | FileAccess.FILE_READ_ATTRIBUTES, CreateDisposition.OPEN, CreateOptions.NON_DIRECTORY_FILE);
  const head = await compoundOpen(tree, req, readOp(0n, chunk), (meta, [resp]) => ({
    data: readBytes(resp!), size: meta.endOfFile,
  }));
  if (BigInt(head.data.length) >= head.size) return head.data;
  return Open.withOpen(tree, req, async (open) => {
    const rest = open.meta.endOfFile - BigInt(head.data.length);
    if (rest <= 0n) return head.data;
    const tail = await readAt(open, BigInt(head.data.length), Number(rest));
    return Buffer.concat([head.data, tail]);
  });
}

/** Up to `length` bytes at `offset` (fewer at EOF). Single-chunk reads compound; longer ones use an open handle. */
export async function readRangePath(tree: Tree, filename: string, offset: number, length: number): Promise<Buffer> {
  const req = request(filename, FileAccess.FILE_READ_DATA | FileAccess.FILE_READ_ATTRIBUTES, CreateDisposition.OPEN, CreateOptions.NON_DIRECTORY_FILE);
  const clampTo = (meta: CreateResponse): number => Math.min(length, Number(meta.endOfFile) - offset);
  if (length <= readChunkSizeFor(tree.conn)) {
    const result = await compoundOpen(tree, req, readOp(BigInt(offset), length), (meta, [resp]) => {
      const want = clampTo(meta);
      if (want <= 0) return Buffer.alloc(0);
      const data = readBytes(resp!);
      // A short read short of EOF is the server's choice; let the handle path re-issue the remainder.
      return data.length >= want ? data : undefined;
    });
    if (result !== undefined) return result;
  }
  return Open.withOpen(tree, req, async (open) => {
    const want = clampTo(open.meta);
    return want <= 0 ? Buffer.alloc(0) : readAt(open, BigInt(offset), want);
  });
}

/** Writes `data` at `offset` with the given disposition; data that fits one WRITE compounds with CREATE and CLOSE. */
export async function writePath(tree: Tree, filename: string, offset: number, data: Buffer, disposition: number): Promise<void> {
  const req = request(filename, FileAccess.GENERIC_WRITE | FileAccess.FILE_READ_ATTRIBUTES, disposition, CreateOptions.NON_DIRECTORY_FILE);
  let written = 0;
  if (data.length > 0 && data.length <= writeChunkSizeFor(tree)) {
    written = await compoundOpen(tree, req,
      (fileId) => [{
        command: SmbCommand.WRITE,
        body: encodeWriteRequest({ fileId, offset: BigInt(offset), data }),
        creditCharge: creditChargeFor(data.length),
      }],
      (_meta, [resp]) => {
        expectSuccess(resp!, "WRITE");
        return decodeWriteResponse(resp!.body);
      });
    if (written >= data.length) return;
  }
  // Empty data, large data, or a short write: continue through a handle. Never truncate again.
  const reopen = { ...req, createDisposition: disposition === CreateDisposition.OVERWRITE_IF && written === 0 ? disposition : CreateDisposition.OPEN_IF };
  await Open.withOpen(tree, reopen, (open) => writeAll(open, BigInt(offset + written), data.subarray(written)));
}

function writeChunkSizeFor(tree: Tree): number {
  const conn = tree.conn;
  return conn.maxIoSize(conn.state?.maxWriteSize ?? 1 << 16);
}
