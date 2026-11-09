import type { Open } from "./open.js";
import { encodeReadRequest, decodeReadResponse } from "../wire/structs/read.js";
import { SmbCommand, NTStatus, isSuccess, statusName } from "../wire/commands.js";
import { SmbError } from "../errors.js";
import { creditChargeFor, type Connection } from "../connection/connection.js";
import { mapConcurrent, planRanges } from "./pool.js";

const DEFAULT_MAX_READ = 1 << 16; // 64 KiB, the only size every server must accept
/** Concurrent READs issued per call (depth 4-8 reaches link rate in benchmarks). */
const READ_CONCURRENCY = 8;

/** Bytes per READ request on this connection (see Connection.maxIoSize). */
export function readChunkSize(open: Open): number {
  return readChunkSizeFor(open.tree.conn);
}

export function readChunkSizeFor(conn: Connection): number {
  return conn.maxIoSize(conn.state?.maxReadSize ?? DEFAULT_MAX_READ);
}

/** Reads `length` bytes from offset 0, pipelining several READs. Stops early at EOF. */
export async function readAll(open: Open, length: bigint): Promise<Buffer> {
  const ranges = planRanges(0n, length, readChunkSize(open));
  const parts = await mapConcurrent(ranges, READ_CONCURRENCY, (r) => readAt(open, r.offset, r.length));
  // readAt only returns fewer bytes than asked at EOF, so the first short part ends the data.
  const end = parts.findIndex((p, i) => p.length < ranges[i]!.length);
  return Buffer.concat(end === -1 ? parts : parts.slice(0, end + 1));
}

/** One SMB2 READ of at most `length` bytes; may return fewer, and empty at EOF. */
function readOnce(open: Open, offset: bigint, length: number): Promise<Buffer> {
  return open.tree.conn.withIoBudget(length, () => readOnceUnbudgeted(open, offset, length));
}

async function readOnceUnbudgeted(open: Open, offset: bigint, length: number): Promise<Buffer> {
  const body = encodeReadRequest({ fileId: open.fileId, offset, length });
  const signing = open.tree.session.makeSigning();
  const resp = await open.tree.conn.send(SmbCommand.READ, body, {
    sessionId: open.tree.session.sessionId,
    treeId: open.tree.treeId,
    ...(signing !== undefined ? { signing } : {}),
    encrypt: open.tree.encryptRequired,
    creditCharge: creditChargeFor(length),
  });
  if (resp.header.status === NTStatus.STATUS_END_OF_FILE) return Buffer.alloc(0);
  if (!isSuccess(resp.header.status)) {
    throw new SmbError({ status: resp.header.status, message: `READ failed: ${statusName(resp.header.status)}` });
  }
  return decodeReadResponse(resp.body, 64);
}

/** Reads one chunk, re-issuing after a short read; returns fewer bytes than asked only at EOF. */
async function readChunk(open: Open, offset: bigint, length: number): Promise<Buffer> {
  const first = await readOnce(open, offset, length);
  if (first.length === 0 || first.length >= length) return first;
  const parts = [first];
  let got = first.length;
  while (got < length) {
    const part = await readOnce(open, offset + BigInt(got), length - got);
    if (part.length === 0) break;
    parts.push(part);
    got += part.length;
  }
  return Buffer.concat(parts);
}

/**
 * Reads up to `length` bytes at `offset`, splitting the range into chunks and
 * keeping up to READ_CONCURRENCY READs in flight. Returns fewer bytes only at EOF.
 */
export async function readAt(open: Open, offset: bigint, length: number): Promise<Buffer> {
  const ranges = planRanges(offset, BigInt(length), readChunkSize(open));
  if (ranges.length === 1) return readChunk(open, ranges[0]!.offset, ranges[0]!.length);
  const parts = await mapConcurrent(ranges, READ_CONCURRENCY, (r) => readChunk(open, r.offset, r.length));
  // A chunk is short only at EOF, so the first short chunk ends the data.
  const end = parts.findIndex((p, i) => p.length < ranges[i]!.length);
  return Buffer.concat(end === -1 ? parts : parts.slice(0, end + 1));
}

/**
 * Reads several independent ranges, sharing one pipeline across all their chunks
 * so the READ depth stays bounded however many ranges are asked for.
 */
export async function readMany(
  open: Open,
  ranges: readonly { offset: bigint; length: number }[],
): Promise<Buffer[]> {
  const chunk = readChunkSize(open);
  const planned = ranges.map((r) => planRanges(r.offset, BigInt(r.length), chunk));
  const parts = await mapConcurrent(planned.flat(), READ_CONCURRENCY, (r) => readChunk(open, r.offset, r.length));
  let index = 0;
  return planned.map((chunks) => {
    const own = parts.slice(index, (index += chunks.length));
    // A chunk is short only at EOF, so the first short chunk ends this range.
    const end = own.findIndex((p, i) => p.length < chunks[i]!.length);
    return Buffer.concat(end === -1 ? own : own.slice(0, end + 1));
  });
}
