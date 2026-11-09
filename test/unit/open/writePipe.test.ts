import { describe, it, expect } from "vitest";
import { createWritePipe } from "../../../src/open/writePipe.js";
import type { Open } from "../../../src/open/open.js";

function fakeOpen(failAt?: bigint) {
  let inflight = 0, peak = 0;
  const offsets: bigint[] = [];
  const send = async (_c: number, body: Buffer) => {
    inflight++; peak = Math.max(peak, inflight);
    const offset = body.readBigUInt64LE(8);
    await new Promise((r) => setTimeout(r, 5));
    inflight--; offsets.push(offset);
    const length = body.readUInt32LE(4);
    const ok = offset !== failAt;
    const reply = Buffer.alloc(8); reply.writeUInt16LE(17); reply.writeUInt32LE(length, 4);
    return { header: { status: ok ? 0 : 0xc00000d1 }, body: reply };
  };
  const conn = { maxIoSize: () => 100, state: { maxWriteSize: 100 }, send, withIoBudget: (_n: number, fn: () => Promise<unknown>) => fn() };
  const open = { fileId: Buffer.alloc(16), tree: { conn, session: { sessionId: 1n, makeSigning: () => undefined }, treeId: 1, encryptRequired: false } };
  return { open: open as unknown as Open, peak: () => peak, offsets };
}

describe("write pipe", () => {
  it("keeps several writes in flight from sequential callers, at the right offsets", async () => {
    const { open, peak, offsets } = fakeOpen();
    const pipe = createWritePipe(open, 1000n, 4);
    for (let i = 0; i < 10; i++) await pipe.write(Buffer.alloc(100, i));
    await pipe.flush();
    expect(peak()).toBeGreaterThan(1);
    expect(peak()).toBeLessThanOrEqual(4);
    expect([...offsets].sort((a, b) => Number(a - b))).toEqual(Array.from({ length: 10 }, (_, i) => 1000n + BigInt(i * 100)));
  });

  it("surfaces the first failure from write and flush", async () => {
    const { open } = fakeOpen(1200n);
    const pipe = createWritePipe(open, 1000n, 2);
    let failed: unknown;
    try { for (let i = 0; i < 10; i++) await pipe.write(Buffer.alloc(100)); await pipe.flush(); } catch (e) { failed = e; }
    expect(failed).toBeInstanceOf(Error);
    expect((failed as Error).message).toMatch(/WRITE failed/);
    await expect(pipe.flush()).rejects.toBe(failed);
  });
});
