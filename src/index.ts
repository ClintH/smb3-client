export const VERSION = "0.0.0";
export { Client } from "./client.js";
export { SmbError, SmbAuthError, SmbProtocolError } from "./errors.js";
export type { ClientOptions, FileStat, Dirent, ShareInfo, ChangeEvent, ChangeAction } from "./types.js";

export { StorageHandle } from './storage.js';
export type { StorageOpenOptions, StorageStat } from './storage.js';
