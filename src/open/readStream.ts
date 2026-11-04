import { Readable } from "node:stream";
import type { Open } from "./open.js";
import { readAt, readChunkSize } from "./read.js";

export interface ReadStreamOptions {
  start?: bigint;
  end?: bigint; // inclusive byte offset of the last byte to read
  highWaterMark?: number;
  concurrency?: number;
}

export function createReadStream(open: Open, opts: ReadStreamOptions = {}): Readable {
  const start = opts.start ?? 0n;
  const totalEnd = opts.end ?? open.meta.endOfFile - 1n;
  if (totalEnd < start) {
    return Readable.from([], { objectMode: false });
  }
  const max = readChunkSize(open);
  const chunkSize = Math.min(max, opts.highWaterMark ?? max);
  const concurrency = Math.max(1, Math.min(opts.concurrency ?? 4, 8));

  let nextOffset = start;
  let outOffset = start; // next offset we may push
  const buffers = new Map<string, Buffer>(); // offset string → buffer
  let inFlight = 0;
  let pushing = false;
  let closed = false;

  const stream = new Readable({
    highWaterMark: chunkSize,
    read() {
      pushing = true;
      drain();
    },
  });

  function drain(): void {
    while (pushing && buffers.has(outOffset.toString())) {
      const k = outOffset.toString();
      const buf = buffers.get(k)!;
      buffers.delete(k);
      pushing = stream.push(buf);
      outOffset += BigInt(buf.length);
    }
    if (outOffset > totalEnd && inFlight === 0 && buffers.size === 0 && !closed) {
      closed = true;
      stream.push(null);
      return;
    }
    // Bound read-ahead (in flight + completed but not yet consumed) so a slow consumer
    // cannot make us buffer the whole file.
    while (inFlight < concurrency && inFlight + buffers.size < concurrency * 2 && nextOffset <= totalEnd) {
      const remaining = totalEnd - nextOffset + 1n;
      const want = remaining > BigInt(chunkSize) ? BigInt(chunkSize) : remaining;
      const offset = nextOffset;
      const length = Number(want);
      nextOffset += want;
      inFlight++;
      readAt(open, offset, length).then(
        (buf) => {
          inFlight--;
          buffers.set(offset.toString(), buf);
          drain();
        },
        (err) => {
          stream.destroy(err);
        },
      );
    }
  }

  return stream;
}
