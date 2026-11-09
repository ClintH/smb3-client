import type { Tree } from "../tree/tree.js";
import type { SmbHeader } from "../wire/smb2-header.js";
import { encodeCreateRequest, decodeCreateResponse, type CreateRequest, type CreateResponse } from "../wire/structs/create.js";
import { encodeCloseRequest, decodeCloseResponse } from "../wire/structs/close.js";
import { SmbCommand, isSuccess, statusName } from "../wire/commands.js";
import { SmbError } from "../errors.js";

/** FileId that a related command resolves to the previous command's file (MS-SMB2 §3.3.5.2.7.2). */
export const RELATED_FILE_ID = Buffer.alloc(16, 0xff);

export interface CompoundOp {
  command: number;
  body: Buffer;
  creditCharge?: number;
}

export interface Response {
  header: SmbHeader;
  body: Buffer;
}

/** Throws an SmbError unless `resp` succeeded. */
export function expectSuccess(resp: Response, what: string): void {
  if (!isSuccess(resp.header.status)) {
    throw new SmbError({ status: resp.header.status, message: `${what} failed: ${statusName(resp.header.status)}` });
  }
}

function sendOne(tree: Tree, command: number, body: Buffer, creditCharge: number): Promise<Response> {
  const signing = tree.session.makeSigning();
  return tree.conn.send(command, body, {
    sessionId: tree.session.sessionId,
    treeId: tree.treeId,
    ...(signing !== undefined ? { signing } : {}),
    encrypt: tree.encryptRequired,
    creditCharge,
  });
}

/**
 * CREATE, then `ops`, then CLOSE, in one round trip. `makeOps` receives the FileId
 * to put in the bodies: the related-operations sentinel when compounding, the real
 * FileId on the sequential fallback used if the connection has not been granted
 * enough credits yet. `interpret` inspects the CREATE result and the `ops`
 * responses (not yet checked) and may throw. As with `Open.withOpen`, a CLOSE
 * failure is the operation's failure once everything else succeeded, because
 * CLOSE reports the outcome of DELETE_ON_CLOSE.
 */
export async function compoundOpen<T>(
  tree: Tree,
  req: CreateRequest,
  makeOps: (fileId: Buffer) => CompoundOp[],
  interpret: (meta: CreateResponse, responses: Response[]) => T,
): Promise<T> {
  const related = makeOps(RELATED_FILE_ID);
  const total = 2 + related.reduce((n, op) => n + (op.creditCharge ?? 1), 0);
  if (!tree.conn.canCompound(total)) return sequentialOpen(tree, req, makeOps, interpret);

  const signing = tree.session.makeSigning();
  const responses = await tree.conn.sendCompound(
    [
      { command: SmbCommand.CREATE, body: encodeCreateRequest(req) },
      ...related,
      { command: SmbCommand.CLOSE, body: encodeCloseRequest(RELATED_FILE_ID) },
    ],
    {
      sessionId: tree.session.sessionId,
      treeId: tree.treeId,
      ...(signing !== undefined ? { signing } : {}),
      encrypt: tree.encryptRequired,
    },
  );
  const [create, ...rest] = responses as [Response, ...Response[]];
  const close = rest.pop()!;
  expectSuccess(create, "CREATE");
  const meta = decodeCreateResponse(create.body);
  let value: T;
  try {
    value = interpret(meta, rest);
  } catch (err) {
    // The server may have skipped the related CLOSE after a failed command; closing a closed handle is harmless.
    if (!isSuccess(close.header.status)) {
      try { await sendOne(tree, SmbCommand.CLOSE, encodeCloseRequest(meta.fileId), 1); } catch { /* keep primary error */ }
    }
    throw err;
  }
  expectSuccess(close, "CLOSE");
  decodeCloseResponse(close.body);
  return value;
}

async function sequentialOpen<T>(
  tree: Tree,
  req: CreateRequest,
  makeOps: (fileId: Buffer) => CompoundOp[],
  interpret: (meta: CreateResponse, responses: Response[]) => T,
): Promise<T> {
  const create = await sendOne(tree, SmbCommand.CREATE, encodeCreateRequest(req), 1);
  expectSuccess(create, "CREATE");
  const meta = decodeCreateResponse(create.body);
  let value: T;
  try {
    const responses: Response[] = [];
    for (const op of makeOps(meta.fileId)) responses.push(await sendOne(tree, op.command, op.body, op.creditCharge ?? 1));
    value = interpret(meta, responses);
  } catch (err) {
    try { await sendOne(tree, SmbCommand.CLOSE, encodeCloseRequest(meta.fileId), 1); } catch { /* keep primary error */ }
    throw err;
  }
  const close = await sendOne(tree, SmbCommand.CLOSE, encodeCloseRequest(meta.fileId), 1);
  expectSuccess(close, "CLOSE");
  decodeCloseResponse(close.body);
  return value;
}
