import { describe, expect, it, vi } from 'vitest';
import { StorageHandle } from '../../src/storage.js';
import { SmbCommand } from '../../src/wire/commands.js';

function fixture(status = 0) {
  const info = Buffer.alloc(100);
  info.writeBigUInt64LE(133486382450000000n, 16);
  info.writeBigUInt64LE(12n, 48); info.writeUInt32LE(1, 56);
  info.writeBigUInt64LE(18446744073709550001n, 64);
  const query = Buffer.alloc(8 + info.length);
  query.writeUInt16LE(9); query.writeUInt16LE(72, 2); query.writeUInt32LE(info.length, 4); info.copy(query, 8);
  const send = vi.fn(async (command: number) => ({ header: { status },
    body: command === SmbCommand.QUERY_INFO ? query : command === SmbCommand.FLUSH ? Buffer.from([4, 0, 0, 0]) : Buffer.from([2, 0]) }));
  const close = vi.fn(async () => {});
  const open = { fileId: Buffer.alloc(16, 7), meta: { fileAttributes: 0 }, close,
    tree: { conn: { send }, session: { sessionId: 1n, makeSigning: () => undefined }, treeId: 1, encryptRequired: true } };
  const handle = new StorageHandle(open as unknown as ConstructorParameters<typeof StorageHandle>[0]);
  return { handle, send, close };
}

describe('persistent storage handle', () => {
  it('returns lossless stable file IDs and current size from QUERY_INFO', async () => {
    const { handle } = fixture();
    expect(await handle.stat()).toMatchObject({ id: '18446744073709550001', nlink: 1, size: 12, reparsePoint: false });
  });

  it('issues a real SMB FLUSH with the held file ID', async () => {
    const { handle, send } = fixture(); await handle.sync();
    const call = send.mock.calls[0] as unknown as [number, Buffer, { encrypt: boolean }];
    expect(call[0]).toBe(SmbCommand.FLUSH); expect(call[1].readUInt16LE(0)).toBe(24);
    expect(call[1].subarray(8)).toEqual(Buffer.alloc(16, 7)); expect(call[2].encrypt).toBe(true);
  });

  it('sets EOF and timestamps using the same held object', async () => {
    const { handle, send } = fixture(); await handle.truncate(12345);
    let body = (send.mock.calls[0] as unknown as [number, Buffer])[1];
    expect(body[3]).toBe(20); expect(body.readBigUInt64LE(32)).toBe(12345n);
    await handle.setMetadata({ mtime: new Date('2024-01-02T03:04:05Z') });
    body = (send.mock.calls[1] as unknown as [number, Buffer])[1];
    expect(body[3]).toBe(4); expect(body.readBigUInt64LE(48)).toBe(133486382450000000n);
  });

  it('refuses server failures and unsafe ranges without claiming completion', async () => {
    const { handle } = fixture(0xc0000022);
    await expect(handle.sync()).rejects.toMatchObject({ code: 'EACCES' });
    await expect(handle.truncate(-1)).rejects.toThrow(RangeError);
    await expect(handle.rename('../public')).rejects.toThrow();
  });

  it('encodes explicit no-replace and replacement policies and delegates close', async () => {
    const { handle, send, close } = fixture();
    await handle.rename('out/file'); await handle.rename('out/file', true);
    expect((send.mock.calls[0] as unknown as [number, Buffer])[1][32]).toBe(0);
    expect((send.mock.calls[1] as unknown as [number, Buffer])[1][32]).toBe(1);
    expect((send.mock.calls[0] as unknown as [number, Buffer])[1].subarray(52).toString('utf16le')).toBe('out\\file');
    await handle.close(); expect(close).toHaveBeenCalledOnce();
  });
});
