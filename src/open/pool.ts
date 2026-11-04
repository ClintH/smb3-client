export interface Range {
  offset: bigint;
  length: number;
}

/** Splits [offset, offset + total) into consecutive ranges of at most `chunk` bytes. */
export function planRanges(offset: bigint, total: bigint, chunk: number): Range[] {
  const ranges: Range[] = [];
  const step = BigInt(chunk);
  for (let done = 0n; done < total; done += step) {
    const left = total - done;
    ranges.push({ offset: offset + done, length: Number(left < step ? left : step) });
  }
  return ranges;
}

/**
 * Maps `items` through `fn` with at most `limit` calls in flight, returning
 * results in input order. After the first failure no new calls are started and
 * the first error is thrown once the calls already in flight have settled.
 */
export async function mapConcurrent<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  let failure: { error: unknown } | undefined;
  const worker = async (): Promise<void> => {
    while (failure === undefined && next < items.length) {
      const i = next++;
      try {
        results[i] = await fn(items[i]!);
      } catch (error) {
        failure ??= { error };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  if (failure !== undefined) throw failure.error;
  return results;
}
