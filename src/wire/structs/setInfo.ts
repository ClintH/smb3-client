import { Writer } from "../buffer.js";
import { InfoType, FileInformationClass } from "./queryInfo.js";

export interface SetInfoRequest {
  infoType: number;
  fileInformationClass: number;
  fileId: Buffer;
  buffer: Buffer;
  additionalInformation?: number;
}

export function encodeSetInfoRequest(req: SetInfoRequest): Buffer {
  const w = new Writer();
  w.u16(33);
  w.u8(req.infoType);
  w.u8(req.fileInformationClass);
  w.u32(req.buffer.length);
  w.u16(64 + 32); // BufferOffset
  w.u16(0); // Reserved
  w.u32(req.additionalInformation ?? 0);
  w.bytes(req.fileId);
  w.bytes(req.buffer.length === 0 ? Buffer.from([0]) : req.buffer);
  return w.buffer();
}

export interface FileRenameInformationInputs {
  replaceIfExists: boolean;
  fileName: string;
  rootDirectory?: bigint;
}

export function encodeFileRenameInformation(inp: FileRenameInformationInputs): Buffer {
  const name = Buffer.from(inp.fileName, "utf16le");
  const w = new Writer();
  w.u8(inp.replaceIfExists ? 1 : 0);
  w.bytes(Buffer.alloc(7)); // Reserved (7 bytes pad to 8)
  w.u64(inp.rootDirectory ?? 0n);
  w.u32(name.length);
  w.bytes(name);
  return w.buffer();
}

/** FileDispositionInformation ([MS-FSCC] 2.4.11): a single DeletePending byte. */
export function encodeFileDispositionInformation(deletePending: boolean): Buffer {
  return Buffer.from([deletePending ? 1 : 0]);
}

export { InfoType, FileInformationClass };
