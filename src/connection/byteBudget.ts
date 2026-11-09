interface Waiter {
  bytes: number;
  start: () => void;
}

export interface ByteBudget {
  /** Runs `fn` once `bytes` fit in the budget (FIFO), releasing them when it settles. */
  run<T>(bytes: number, fn: () => Promise<T>): Promise<T>;
}

/**
 * Counting semaphore over bytes. A request larger than the whole budget is
 * admitted alone, so oversized requests cannot deadlock.
 */
export function createByteBudget(limit: number): ByteBudget {
  let used = 0;
  const waiters: Waiter[] = [];
  const fits = (bytes: number): boolean => used === 0 || used + bytes <= limit;
  const admit = (): void => {
    while (waiters.length > 0 && fits(waiters[0]!.bytes)) {
      const waiter = waiters.shift()!;
      used += waiter.bytes;
      waiter.start();
    }
  };
  return {
    async run(bytes, fn) {
      if (waiters.length > 0 || !fits(bytes)) {
        await new Promise<void>((start) => waiters.push({ bytes, start }));
      } else {
        used += bytes;
      }
      try { return await fn(); }
      finally { used -= bytes; admit(); }
    },
  };
}
