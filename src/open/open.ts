import type { Tree } from "../tree/tree.js";
import {
  encodeCreateRequest,
  decodeCreateResponse,
  CreateRequest,
  CreateResponse,
} from "../wire/structs/create.js";
import { encodeCloseRequest, decodeCloseResponse } from "../wire/structs/close.js";
import { SmbCommand, isSuccess, statusName } from "../wire/commands.js";
import { SmbError } from "../errors.js";

export class Open {
  private closed = false;
  private constructor(
    public readonly tree: Tree,
    public readonly fileId: Buffer,
    public readonly meta: CreateResponse,
  ) {}

  static async create(tree: Tree, req: CreateRequest): Promise<Open> {
    const body = encodeCreateRequest(req);
    const signing = tree.session.makeSigning();
    const resp = await tree.conn.send(SmbCommand.CREATE, body, {
      sessionId: tree.session.sessionId,
      treeId: tree.treeId,
      ...(signing !== undefined ? { signing } : {}),
      encrypt: tree.encryptRequired,
      creditCharge: 1,
    });
    if (!isSuccess(resp.header.status)) {
      throw new SmbError({ status: resp.header.status, message: `CREATE failed: ${statusName(resp.header.status)}` });
    }
    const meta = decodeCreateResponse(resp.body);
    return new Open(tree, meta.fileId, meta);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const body = encodeCloseRequest(this.fileId);
    const signing = this.tree.session.makeSigning();
    const resp = await this.tree.conn.send(SmbCommand.CLOSE, body, {
      sessionId: this.tree.session.sessionId,
      treeId: this.tree.treeId,
      ...(signing !== undefined ? { signing } : {}),
      encrypt: this.tree.encryptRequired,
      creditCharge: 1,
    });
    if (!isSuccess(resp.header.status)) {
      throw new SmbError({ status: resp.header.status, message: `CLOSE failed: ${statusName(resp.header.status)}` });
    }
    decodeCloseResponse(resp.body);
  }

  static async withOpen<T>(tree: Tree, req: CreateRequest, fn: (o: Open) => Promise<T>): Promise<T> {
    const open = await Open.create(tree, req);
    let result: T;
    try {
      result = await fn(open);
    } catch (err) {
      // Keep the primary error; a secondary close failure must not mask it.
      try { await open.close(); } catch { /* swallow secondary close error */ }
      throw err;
    }
    // The CLOSE response carries the outcome of DELETE_ON_CLOSE (rm/rmdir), so
    // on the success path its failure is the operation's failure.
    await open.close();
    return result;
  }
}
