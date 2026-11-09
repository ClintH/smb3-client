import type { Open } from "./open.js";
import { writeAll } from "./write.js";

/** Calls a pipe allows to be outstanding before `write` applies backpressure. */
const DEFAULT_DEPTH = 4;

export interface WritePipe {
  /**
   * Queues `data` at the pipe's cursor and advances it. Resolves once the write is
   * in flight and the pipe has room again, so a sequential caller keeps several
   * WRITEs outstanding. The buffer must not change until `flush` resolves.
   * Rejects with the first failure of any earlier write.
   */
  write(data: Buffer): Promise<void>;
  /** Resolves when every queued write has completed; rejects with the first failure. */
  flush(): Promise<void>;
}

/** Push-based writer over an open handle: bytes go out as the credit window and byte budget allow. */
export function createWritePipe(open: Open, start = 0n, depth = DEFAULT_DEPTH): WritePipe {
  let cursor = start;
  let failure: { error: unknown } | undefined;
  const pending = new Set<Promise<void>>();

  const settled = (): Promise<void> => (failure === undefined ? Promise.resolve() : Promise.reject(failure.error));

  return {
    async write(data) {
      await settled();
      const task = writeAll(open, cursor, data).catch((error: unknown) => {
        failure ??= { error };
      });
      cursor += BigInt(data.length);
      const tracked = task.finally(() => pending.delete(tracked));
      pending.add(tracked);
      while (pending.size >= depth && failure === undefined) await Promise.race(pending);
      await settled();
    },
    async flush() {
      await Promise.all(pending);
      await settled();
    },
  };
}
