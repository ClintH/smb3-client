export interface FileStat {
  size: number;
  isFile: boolean;
  isDirectory: boolean;
  attributes: number;
  readonly: boolean;
  hidden: boolean;
  system: boolean;
  archive: boolean;
  ctime: Date;
  atime: Date;
  mtime: Date;
  changeTime: Date;
}

export interface Dirent {
  name: string;
  isFile: () => boolean;
  isDirectory: () => boolean;
  /** Size in bytes (`EndOfFile`). Servers usually report 0 for directories. Clamped to `Number.MAX_SAFE_INTEGER`. */
  size: number;
  /** Raw SMB2 file attributes (same meaning as `FileStat.attributes`). */
  attributes: number;
  /** Reparse tag (e.g. `IO_REPARSE_TAG_SYMLINK`) when `attributes` has FILE_ATTRIBUTE_REPARSE_POINT and the server reported one; else `undefined`. */
  reparseTag?: number;
  /** Last write time. */
  mtime: Date;
  /** Creation time (same meaning as `FileStat.ctime`). A server that reports none yields `new Date(0)`. */
  ctime: Date;
}

export interface ShareInfo {
  name: string;
  type: "disk" | "ipc" | "print" | "special";
  comment: string;
}

export type ChangeAction =
  | "added"
  | "removed"
  | "modified"
  | "renamedOldName"
  | "renamedNewName";

export interface ChangeEvent {
  action: ChangeAction;
  path: string;
}

export interface ClientOptions {
  host: string;
  port?: number;
  domain?: string;
  username: string;
  password: string;
  connectTimeout?: number;
  /** Abort TCP establishment before protocol setup. */
  signal?: AbortSignal;
  requestTimeout?: number;
  signing?: "disabled" | "if-offered" | "required";
  encryption?: "required" | "if-offered" | "disabled";
}
