import { afterEach, describe, expect, it, vi } from 'vitest';
import { Connection } from '../../../src/connection/connection.js';
import { SmbCommand } from '../../../src/wire/commands.js';
import { FakeTransport } from '../../helpers/fakeTransport.js';

afterEach(() => vi.useRealTimers());

describe('connection lifecycle and request deadlines', () => {
  it('times out requests and releases both in-flight and credit-waiting callers', async () => {
    vi.useFakeTimers();
    const conn = new Connection(new FakeTransport(), { requestTimeoutMs: 20 });
    const results = Promise.allSettled([conn.send(SmbCommand.READ, Buffer.alloc(0)), conn.send(SmbCommand.WRITE, Buffer.alloc(0))]);
    await vi.advanceTimersByTimeAsync(20);
    const settled = await results;
    expect(settled.every(result => result.status === 'rejected' && result.reason.code === 'ETIMEDOUT')).toBe(true);
    await expect(conn.send(SmbCommand.READ, Buffer.alloc(0))).rejects.toThrow('connection closed');
  });

  it('explicit close rejects pending operations and blocked credit acquisition', async () => {
    const conn = new Connection(new FakeTransport());
    const results = Promise.allSettled([conn.send(SmbCommand.READ, Buffer.alloc(0)), conn.send(SmbCommand.WRITE, Buffer.alloc(0))]);
    await Promise.resolve(); conn.close();
    expect((await results).every(result => result.status === 'rejected')).toBe(true);
  });

  it('leaves long-lived change notifications outside ordinary request deadlines', async () => {
    vi.useFakeTimers();
    const conn = new Connection(new FakeTransport(), { requestTimeoutMs: 20 });
    let settled = false;
    const operation = conn.send(SmbCommand.CHANGE_NOTIFY, Buffer.alloc(0)).catch(() => { settled = true; });
    await vi.advanceTimersByTimeAsync(100); expect(settled).toBe(false);
    conn.close(); await operation; expect(settled).toBe(true);
  });
});
