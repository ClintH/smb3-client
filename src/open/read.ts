import type { Open } from "./open.js";
import { encodeReadRequest, decodeReadResponse } from "../wire/structs/read.js";
import { SmbCommand, NTStatus, isSuccess, statusName } from "../wire/commands.js";
import { SmbError } from "../errors.js";
import { creditChargeFor } from "../connection/connection.js";
import { mapConcurrent, planRanges } from "./pool.js";

const DEFAULT_MAX_READ = 1 << 16; // 64 KiB, the only size every server must accept
/** Concurrent READs issued by readAll. */
const READ_CONCURRENCY = 4;

/** Bytes per READ request on this connection (see Connection.maxIoSize). */
export function readChunkSize(open: Open): number {
  const conn = open.tree.conn;
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
async function readOnce(open: Open, offset: bigint, length: number): Promise<Buffer> {
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

/** Reads up to `length` bytes at `offset`, issuing as many sequential READs as the chunk size requires. */
export async function readAt(open: Open, offset: bigint, length: number): Promise<Buffer> {
  const chunk = readChunkSize(open);
  const parts: Buffer[] = [];
  let got = 0;
  while (got < length) {
    const part = await readOnce(open, offset + BigInt(got), Math.min(chunk, length - got));
    if (part.length === 0) break;
    parts.push(part);
    got += part.length;
  }
  return parts.length === 1 ? parts[0]! : Buffer.concat(parts);
}
