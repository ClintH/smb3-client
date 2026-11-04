import type { Open } from "./open.js";
import { encodeWriteRequest, decodeWriteResponse } from "../wire/structs/write.js";
import { SmbCommand, isSuccess, statusName } from "../wire/commands.js";
import { SmbError } from "../errors.js";
import { creditChargeFor } from "../connection/connection.js";
import { mapConcurrent, planRanges } from "./pool.js";

const DEFAULT_MAX_WRITE = 1 << 16; // 64 KiB, the only size every server must accept
/** Concurrent WRITEs issued by writeAll. */
const WRITE_CONCURRENCY = 4;

/** Bytes per WRITE request on this connection (see Connection.maxIoSize). */
export function writeChunkSize(open: Open): number {
  const conn = open.tree.conn;
  return conn.maxIoSize(conn.state?.maxWriteSize ?? DEFAULT_MAX_WRITE);
}

/** One SMB2 WRITE; resolves to the byte count the server accepted (may be less than `data.length`). */
async function writeOnce(open: Open, offset: bigint, data: Buffer): Promise<number> {
  const body = encodeWriteRequest({ fileId: open.fileId, offset, data });
  const signing = open.tree.session.makeSigning();
  const resp = await open.tree.conn.send(SmbCommand.WRITE, body, {
    sessionId: open.tree.session.sessionId,
    treeId: open.tree.treeId,
    ...(signing !== undefined ? { signing } : {}),
    encrypt: open.tree.encryptRequired,
    creditCharge: creditChargeFor(data.length),
  });
  if (!isSuccess(resp.header.status)) {
    throw new SmbError({ status: resp.header.status, message: `WRITE failed: ${statusName(resp.header.status)}` });
  }
  const count = decodeWriteResponse(resp.body);
  if (count <= 0) throw new Error("WRITE returned zero count");
  return count;
}

/** Writes all of `data` at `offset`, re-issuing the remainder after any short write. */
async function writeFully(open: Open, offset: bigint, data: Buffer): Promise<void> {
  let written = 0;
  while (written < data.length) {
    written += await writeOnce(open, offset + BigInt(written), data.subarray(written));
  }
}

/** Writes `data` at `offset`, pipelining several WRITEs. Writes to distinct ranges, so order is irrelevant. */
export async function writeAll(open: Open, offset: bigint, data: Buffer): Promise<void> {
  const ranges = planRanges(offset, BigInt(data.length), writeChunkSize(open));
  await mapConcurrent(ranges, WRITE_CONCURRENCY, (r) => {
    const start = Number(r.offset - offset);
    return writeFully(open, r.offset, data.subarray(start, start + r.length));
  });
}
