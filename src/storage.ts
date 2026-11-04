import type { Open } from './open/open.js';
import { readAt } from './open/read.js';
import { writeAll } from './open/write.js';
import { metaToStat } from './open/query.js';
import { SmbCommand, isSuccess, statusName } from './wire/commands.js';
import { SmbError } from './errors.js';
import { encodeQueryInfoRequest, decodeQueryInfoResponse, decodeFileAllInformation, InfoType, FileInformationClass } from './wire/structs/queryInfo.js';
import { encodeSetInfoRequest, encodeFileRenameInformation } from './wire/structs/setInfo.js';
import type { FileStat } from './types.js';

export interface StorageOpenOptions {
  read?: boolean;
  write?: boolean;
  writeAttributes?: boolean;
  create?: boolean;
  exclusive?: boolean;
  truncate?: boolean;
  directory?: boolean;
  /** Zero obtains a server-enforced exclusive handle, including across machines. */
  shareAccess?: number;
  deleteOnClose?: boolean;
  deleteAccess?: boolean;
}

export interface StorageStat extends FileStat {
  /** FileInternalInformation.IndexNumber, losslessly represented as a decimal string. */
  id: string;
  nlink: number;
  reparsePoint: boolean;
}

/** Persistent positioned storage handle. No operations implicitly reopen the path. */
export class StorageHandle {
  constructor(private readonly open: Open) {}

  private async request(command: number, body: Buffer): Promise<Buffer> {
    const tree = this.open.tree;
    const signing = tree.session.makeSigning();
    const response = await tree.conn.send(command, body, {
      sessionId: tree.session.sessionId, treeId: tree.treeId,
      ...(signing ? { signing } : {}), encrypt: tree.encryptRequired, creditCharge: 1,
    });
    if (!isSuccess(response.header.status)) throw new SmbError({
      status: response.header.status, message: `Storage operation failed: ${statusName(response.header.status)}`,
    });
    return response.body;
  }

  async stat(): Promise<StorageStat> {
    const response = await this.request(SmbCommand.QUERY_INFO, encodeQueryInfoRequest({
      infoType: InfoType.FILE, fileInformationClass: FileInformationClass.FileAllInformation,
      fileId: this.open.fileId, outputBufferLength: 65536,
    }));
    const bytes = decodeQueryInfoResponse(response);
    if (bytes.length < 100) throw new Error('Truncated FileAllInformation.');
    const info = decodeFileAllInformation(bytes);
    const stat = metaToStat({ ...this.open.meta, ...info });
    const id = bytes.readBigUInt64LE(64);
    if (id === 0n) throw new Error('Server does not expose a stable file identity.');
    return { ...stat, id: id.toString(), nlink: info.numberOfLinks, reparsePoint: (info.fileAttributes & 0x400) !== 0 };
  }

  async read(position: number, length: number): Promise<Buffer> {
    if (!Number.isSafeInteger(position) || position < 0 || !Number.isSafeInteger(length) || length < 0) throw new RangeError('Invalid read range.');
    return readAt(this.open, BigInt(position), length);
  }

  async write(position: number, data: Buffer): Promise<void> {
    if (!Number.isSafeInteger(position) || position < 0 || !Number.isSafeInteger(position + data.length)) throw new RangeError('Invalid write range.');
    await writeAll(this.open, BigInt(position), data);
  }

  async sync(): Promise<void> {
    const body = Buffer.alloc(24); body.writeUInt16LE(24); this.open.fileId.copy(body, 8);
    const response = await this.request(SmbCommand.FLUSH, body);
    if (response.length < 4 || response.readUInt16LE(0) !== 4) throw new Error('Invalid FLUSH response.');
  }

  private async set(infoClass: number, buffer: Buffer): Promise<void> {
    const response = await this.request(SmbCommand.SET_INFO, encodeSetInfoRequest({
      infoType: InfoType.FILE, fileInformationClass: infoClass, fileId: this.open.fileId, buffer,
    }));
    if (response.length < 2 || response.readUInt16LE(0) !== 2) throw new Error('Invalid SET_INFO response.');
  }

  async truncate(size: number): Promise<void> {
    if (!Number.isSafeInteger(size) || size < 0) throw new RangeError('Invalid file size.');
    const buffer = Buffer.alloc(8); buffer.writeBigUInt64LE(BigInt(size));
    await this.set(FileInformationClass.FileEndOfFileInformation, buffer);
  }

  async setMetadata(options: { atime?: Date; mtime?: Date; readonly?: boolean }): Promise<void> {
    const buffer = Buffer.alloc(40);
    const time = (date: Date): bigint => {
      const ms = date.getTime();
      if (!Number.isSafeInteger(ms)) throw new RangeError('Invalid timestamp.');
      const value = (BigInt(ms) + 11644473600000n) * 10000n;
      if (value <= 0n || value > 0xffffffffffffffffn) throw new RangeError('Timestamp outside SMB range.');
      return value;
    };
    if (options.atime) buffer.writeBigUInt64LE(time(options.atime), 8);
    if (options.mtime) buffer.writeBigUInt64LE(time(options.mtime), 16);
    if (options.readonly !== undefined) {
      const stat = await this.stat();
      const attributes = options.readonly ? stat.attributes | 1 : stat.attributes & ~1;
      buffer.writeUInt32LE(attributes || 0x80, 32);
    }
    await this.set(FileInformationClass.FileBasicInformation, buffer);
  }

  /** Target is relative to this handle's share. Existing targets are refused by default. */
  async rename(path: string, replaceIfExists = false): Promise<void> {
    if (path.startsWith('/') || path.includes('\\') || path.split('/').some(part => !part || part === '.' || part === '..')) throw new Error('Invalid rename target.');
    await this.set(FileInformationClass.FileRenameInformation, encodeFileRenameInformation({ fileName: path.replace(/\//g, '\\'), replaceIfExists }));
  }

  async close(): Promise<void> { await this.open.close(); }
}
