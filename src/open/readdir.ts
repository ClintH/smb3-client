import type { Open } from "./open.js";
import {
  encodeQueryDirectoryRequest,
  decodeQueryDirectoryResponse,
  parseFileBothDirectoryInformation,
  QueryDirectoryFlag,
  DirEntry,
} from "../wire/structs/queryDirectory.js";
import { FileInformationClass } from "../wire/structs/queryInfo.js";
import { SmbCommand, NTStatus, isSuccess, statusName } from "../wire/commands.js";
import { SmbError } from "../errors.js";

export async function readdirAll(open: Open, pattern = "*"): Promise<DirEntry[]> {
  const items: DirEntry[] = [];
  let first = true;
  for (;;) {
    const body = encodeQueryDirectoryRequest({
      // FileBothDirectoryInformation (class 3), not FileIdBothDirectoryInformation
      // (class 37): macOS smbd rejects class 37 for QUERY_DIRECTORY with
      // STATUS_NO_SUCH_FILE. Class 3 is honored by macOS, Windows, and Samba.
      fileInformationClass: FileInformationClass.FileBothDirectoryInformation,
      flags: first ? QueryDirectoryFlag.RESTART_SCANS : 0,
      fileIndex: 0,
      fileId: open.fileId,
      searchPattern: first ? pattern : "",
      outputBufferLength: 65536,
    });
    first = false;
    const signing = open.tree.session.makeSigning();
    const resp = await open.tree.conn.send(SmbCommand.QUERY_DIRECTORY, body, {
      sessionId: open.tree.session.sessionId,
      treeId: open.tree.treeId,
      ...(signing !== undefined ? { signing } : {}),
      encrypt: open.tree.encryptRequired,
      creditCharge: 1,
    });
    if (resp.header.status === NTStatus.STATUS_NO_MORE_FILES) break;
    if (!isSuccess(resp.header.status)) {
      throw new SmbError({ status: resp.header.status, message: `QUERY_DIRECTORY failed: ${statusName(resp.header.status)}` });
    }
    const buf = decodeQueryDirectoryResponse(resp.body, 64);
    if (buf.length === 0) break;
    const page = parseFileBothDirectoryInformation(buf);
    for (const e of page) items.push(e);
    if (page.length === 0) break;
  }
  // Filter "." and ".."
  return items.filter((x) => x.fileName !== "." && x.fileName !== "..");
}
