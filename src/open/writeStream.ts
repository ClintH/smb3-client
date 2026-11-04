import { Writable } from "node:stream";
import type { Open } from "./open.js";
import { writeAll, writeChunkSize } from "./write.js";

export interface WriteStreamOptions {
  start?: bigint;
  highWaterMark?: number;
  /** When true (default), CLOSE the underlying handle on stream end. */
  closeOnFinal?: boolean;
}

export function createWriteStream(open: Open, opts: WriteStreamOptions = {}): Writable {
  const hwm = opts.highWaterMark ?? writeChunkSize(open);
  let offset = opts.start ?? 0n;
  const closeOnFinal = opts.closeOnFinal ?? true;

  function flush(buf: Buffer, cb: (err?: Error | null) => void): void {
    writeAll(open, offset, buf).then(
      () => {
        offset += BigInt(buf.length);
        cb();
      },
      (err) => cb(err as Error),
    );
  }

  return new Writable({
    highWaterMark: hwm,
    write(chunk, _enc, cb) {
      flush(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk), cb);
    },
    // Small upstream chunks (e.g. 64 KiB from fs streams) pile up while a WRITE is in
    // flight; send them as one large WRITE instead of many small ones.
    writev(chunks, cb) {
      flush(Buffer.concat(chunks.map((c) => c.chunk as Buffer)), cb);
    },
    final(cb) {
      if (!closeOnFinal) return cb();
      open.close().then(() => cb(), (err) => cb(err as Error));
    },
    destroy(err, cb) {
      if (!closeOnFinal) return cb(err);
      open.close().then(() => cb(err), () => cb(err));
    },
  });
}
