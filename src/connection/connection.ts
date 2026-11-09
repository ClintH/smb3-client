import { randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import type { Transport } from "../transport/socket.js";
import { frame as makeFrame } from "../transport/framer.js";
import { encodeHeader, decodeHeader, SmbHeader, SMB2_HEADER_SIZE } from "../wire/smb2-header.js";
import {
  SmbCommand,
  Dialect,
  HeaderFlag,
  NTStatus,
  SecurityMode,
  Capability,
  isSuccess,
  isPending,
  statusName,
} from "../wire/commands.js";
import { encodeNegotiateRequest, decodeNegotiateResponse, NegotiateResponse } from "../wire/structs/negotiate.js";
import { encodeCancelRequest } from "../wire/structs/cancel.js";
import { CreditWindow } from "./credits.js";
import { createByteBudget } from "./byteBudget.js";
import { PreauthHash } from "./preauth.js";
import { type Encryptor, isTransformHeader } from "./encryption.js";
import { SmbProtocolError } from "../errors.js";

export interface ConnectionOpenOptions {
  clientGuid?: Buffer;
  dialects?: number[];
  capabilities?: number;
  securityMode?: number;
  ciphers?: number[];
}

export interface NegotiatedConnection {
  dialect: number;
  serverGuid: Buffer;
  capabilities: number;
  securityMode: number;
  maxReadSize: number;
  maxWriteSize: number;
  maxTransactSize: number;
  preauthHashAlg?: number;
  preauthSalt?: Buffer;
  cipherIds?: number[];
  securityBuffer: Buffer;
}

interface PendingRequest {
  resolve: (v: { header: SmbHeader; body: Buffer }) => void;
  reject: (err: unknown) => void;
  expectsAsync: boolean;
  encrypted: boolean;
  /** Credits this request consumed, returned to the in-flight accounting on its final response. */
  charge: number;
}

/** Size of one SMB2 credit: the unit of CreditCharge for READ/WRITE (MS-SMB2 §3.1.5.2). */
export const CREDIT_UNIT = 65536;
/** Largest single READ/WRITE we issue, even if the server allows more (matches Linux cifs). */
const MAX_IO_SIZE = 1 << 20;
/** Credit window we try to keep open with the server; it may grant less. */
const TARGET_CREDITS = 512;
/** READ/WRITE payload bytes allowed in flight on one connection at once. */
const MAX_INFLIGHT_BYTES = 8 << 20;

/** Number of credits a READ/WRITE payload of `bytes` consumes. */
export function creditChargeFor(bytes: number): number {
  return Math.max(1, Math.ceil(bytes / CREDIT_UNIT));
}

export interface SendOptions {
  treeId?: number;
  sessionId?: bigint;
  creditCharge?: number;
  flags?: number;
  signing?: { sign: (msg: Buffer) => Buffer };
  encrypt?: boolean;
}

export class Connection extends EventEmitter {
  private nextMessageId: bigint = 0n;
  private pendingByMessageId = new Map<string, PendingRequest>();
  private pendingByAsyncId = new Map<string, PendingRequest>();
  /** Tracks the asyncId assigned by the server for pending async requests, keyed by messageId string. */
  private asyncIdByMessageId = new Map<string, bigint>();
  private credits = new CreditWindow(1);
  /** Credits consumed by requests whose final response has not arrived yet. */
  private inflightCharge = 0;
  /** Most credits we have ever owned at once (available + in flight): what the server has really granted. */
  private peakCredits = 1;
  private preauth = new PreauthHash();
  private negotiated: NegotiatedConnection | null = null;
  private closed = false;
  private verifier: ((frame: Buffer, sig: Buffer) => boolean) | null = null;
  private signCancel: ((msg: Buffer) => Buffer) | null = null;
  private encryptor: Encryptor | null = null;
  private encryptionRequired = false;
  private signingRequired = false;
  private readonly ioBudget = createByteBudget(MAX_INFLIGHT_BYTES);
  /** Requests (or compounds) awaiting a response, for the idle watchdog. */
  private outstanding = 0;
  private lastActivity = Date.now();
  private watchdog: NodeJS.Timeout | undefined;

  constructor(private readonly transport: Transport, private readonly options: { requestTimeoutMs?: number } = {}) {
    super();
    transport.on("message", (msg: Buffer) => this.onMessage(msg));
    transport.on("close", () => this.onClose());
    transport.on("error", (err: Error) => this.onError(err));
  }

  get state(): NegotiatedConnection | null {
    return this.negotiated;
  }

  /**
   * Largest READ/WRITE payload that is safe to send right now. Multi-credit I/O
   * needs LARGE_MTU (MS-SMB2 §3.2.4.1.5); without it the limit is one credit
   * (64 KiB). The size is also bounded by the credits the server has actually
   * granted so far, so a stingy server can never leave a request waiting on
   * credits that will not arrive.
   */
  maxIoSize(serverMax: number): number {
    const largeMtu = ((this.negotiated?.capabilities ?? 0) & Capability.LARGE_MTU) !== 0;
    const ceiling = largeMtu
      ? Math.min(MAX_IO_SIZE, Math.max(1, this.peakCredits) * CREDIT_UNIT)
      : CREDIT_UNIT;
    return Math.max(1, Math.min(serverMax, ceiling));
  }

  async open(opts: ConnectionOpenOptions = {}): Promise<NegotiatedConnection> {
    const dialects = opts.dialects ?? [
      Dialect.SMB_2_1_0,
      Dialect.SMB_3_0_0,
      Dialect.SMB_3_0_2,
      Dialect.SMB_3_1_1,
    ];
    const clientGuid = opts.clientGuid ?? randomBytes(16);
    const preauthSalt = randomBytes(32);
    const reqBody = encodeNegotiateRequest({
      dialects,
      clientGuid,
      capabilities: opts.capabilities ?? Capability.LARGE_MTU,
      securityMode: opts.securityMode ?? SecurityMode.SIGNING_ENABLED,
      preauthSalt,
      ...(opts.ciphers !== undefined ? { ciphers: opts.ciphers } : {}),
    });
    const result = await this.send(SmbCommand.NEGOTIATE, reqBody, { creditCharge: 0 });
    if (!isSuccess(result.header.status)) {
      throw new SmbProtocolError({
        status: result.header.status,
        message: `NEGOTIATE failed: ${statusName(result.header.status)}`,
      });
    }
    const resp: NegotiateResponse = decodeNegotiateResponse(result.body, SMB2_HEADER_SIZE);
    const negotiated: NegotiatedConnection = {
      dialect: resp.dialect,
      serverGuid: resp.serverGuid,
      capabilities: resp.capabilities,
      securityMode: resp.securityMode,
      maxReadSize: resp.maxReadSize,
      maxWriteSize: resp.maxWriteSize,
      maxTransactSize: resp.maxTransactSize,
      securityBuffer: resp.securityBuffer,
      ...(resp.preauthHashAlg !== undefined ? { preauthHashAlg: resp.preauthHashAlg } : {}),
      ...(resp.preauthSalt !== undefined ? { preauthSalt: resp.preauthSalt } : {}),
      ...(resp.cipherIds !== undefined ? { cipherIds: resp.cipherIds } : {}),
    };
    this.negotiated = negotiated;
    return this.negotiated;
  }

  async send(command: number, body: Buffer, opts: SendOptions = {}): Promise<{ header: SmbHeader; body: Buffer }> {
    const [response] = await this.track(command !== SmbCommand.CHANGE_NOTIFY, () =>
      this.dispatch([{ command, body, charge: opts.creditCharge ?? 1, flags: opts.flags ?? 0 }], opts));
    return response!;
  }

  /**
   * Sends several commands as one compound request (MS-SMB2 §3.2.4.1.4) in one
   * round trip. Commands after the first are "related": they inherit the previous
   * command's FileId when their body carries the 0xFF.. sentinel. Responses are
   * returned in request order, however the server frames them.
   */
  async sendCompound(
    items: readonly { command: number; body: Buffer; creditCharge?: number }[],
    opts: Omit<SendOptions, "creditCharge" | "flags"> = {},
  ): Promise<{ header: SmbHeader; body: Buffer }[]> {
    const prepared = items.map((item, i) => ({
      command: item.command,
      body: item.body,
      charge: item.creditCharge ?? 1,
      flags: i > 0 ? HeaderFlag.RELATED_OPERATIONS : 0,
    }));
    return this.track(true, () => this.dispatch(prepared, opts));
  }

  /** True when the credits we have seen granted can cover a compound of `totalCharge` credits. */
  canCompound(totalCharge: number): boolean {
    return !this.closed && this.peakCredits >= totalCharge;
  }

  /**
   * Runs `fn` once `bytes` of READ/WRITE payload fit in the connection-wide
   * in-flight budget. Bounding queued bytes keeps small requests (stat, listings,
   * cancel) from waiting behind a deep queue of bulk transfers.
   */
  withIoBudget<T>(bytes: number, fn: () => Promise<T>): Promise<T> {
    return this.ioBudget.run(bytes, fn);
  }

  /**
   * Idle watchdog: the connection is declared dead only when requests are
   * outstanding and nothing at all has been received for the timeout. A slow but
   * progressing server therefore never trips it, whatever the queue depth.
   */
  private async track<T>(watched: boolean, run: () => Promise<T>): Promise<T> {
    const timeout = this.options.requestTimeoutMs ?? 0;
    if (!timeout || !watched) return run();
    if (this.outstanding++ === 0) this.lastActivity = Date.now();
    this.armWatchdog(timeout, timeout);
    try { return await run(); }
    finally {
      if (--this.outstanding === 0 && this.watchdog !== undefined) {
        clearTimeout(this.watchdog);
        this.watchdog = undefined;
      }
    }
  }

  private armWatchdog(timeout: number, delay: number): void {
    if (this.watchdog !== undefined) return;
    this.watchdog = setTimeout(() => {
      this.watchdog = undefined;
      if (this.outstanding === 0) return;
      const idle = Date.now() - this.lastActivity;
      if (idle < timeout) { this.armWatchdog(timeout, timeout - idle); return; }
      const message = `SMB request timed out: nothing received for ${idle} ms with ${this.outstanding} request(s) outstanding (limit ${timeout} ms)`;
      this.abortConnection(Object.assign(new SmbProtocolError({ status: 0, message }), { code: "ETIMEDOUT" }));
    }, delay);
    this.watchdog.unref();
  }

  private creditRequestFor(charge: number): number {
    // Ask for enough credits to bring our window back up to TARGET_CREDITS once
    // this request completes; this is what lets several requests overlap.
    return Math.min(0xffff, Math.max(1, TARGET_CREDITS - (this.credits.available() + this.inflightCharge) + charge));
  }

  /**
   * Encodes one command of a (possibly compound) message. All but the last
   * command are padded to 8 bytes and carry NextCommand; each is signed on its own.
   */
  private buildSegment(
    s: { command: number; body: Buffer; charge: number; flags: number; messageId: bigint; creditRequest: number },
    opts: SendOptions,
    sign: boolean,
    hasNext: boolean,
  ): Buffer {
    const raw = SMB2_HEADER_SIZE + s.body.length;
    const length = hasNext ? Math.ceil(raw / 8) * 8 : raw;
    const header = encodeHeader({
      command: s.command,
      creditCharge: s.charge,
      creditRequestResponse: s.creditRequest,
      flags: s.flags | (sign ? HeaderFlag.SIGNED : 0),
      messageId: s.messageId,
      sessionId: opts.sessionId ?? 0n,
      treeId: opts.treeId ?? 0,
      status: 0,
      ...(hasNext ? { nextCommand: length } : {}),
    });
    const segment = Buffer.concat([header, s.body, Buffer.alloc(length - raw)]);
    if (sign) opts.signing!.sign(segment).copy(segment, 48); // signature offset within header is 48
    return segment;
  }

  private async dispatch(
    items: readonly { command: number; body: Buffer; charge: number; flags: number }[],
    opts: SendOptions,
  ): Promise<{ header: SmbHeader; body: Buffer }[]> {
    if (this.closed) throw new SmbProtocolError({ status: 0, message: "connection closed" });
    const total = items.reduce((n, item) => n + item.charge, 0);
    if (total > 0) await this.credits.take(total);
    if (this.closed) throw new SmbProtocolError({ status: 0, message: "connection closed" });
    const wantEncrypt = opts.encrypt === true && this.encryptor !== null;
    // Encryption supersedes signing for the same PDU (MS-SMB2 §3.1.4.3): the inner
    // SMB2 header is left unsigned and the TRANSFORM_HEADER's auth tag covers integrity.
    const sign = opts.signing !== undefined && !wantEncrypt;

    const segments: Buffer[] = [];
    const promises: Promise<{ header: SmbHeader; body: Buffer }>[] = [];
    items.forEach((item, i) => {
      // A multi-credit request occupies CreditCharge consecutive message IDs
      // (MS-SMB2 §3.2.4.1.3); the header carries the first.
      const messageId = this.nextMessageId;
      this.nextMessageId += BigInt(Math.max(1, item.charge));
      this.inflightCharge += item.charge;
      const segment = this.buildSegment(
        { ...item, messageId, creditRequest: this.creditRequestFor(item.charge) },
        opts, sign, i < items.length - 1,
      );
      // Pre-auth hash always feeds on the plaintext PDU. NEGOTIATE and the first
      // SESSION_SETUP can't be encrypted (no keys yet).
      if (item.command === SmbCommand.NEGOTIATE || item.command === SmbCommand.SESSION_SETUP) {
        this.preauth.update(segment);
      }
      segments.push(segment);
      promises.push(new Promise((resolve, reject) => {
        this.pendingByMessageId.set(messageId.toString(), {
          resolve,
          reject,
          charge: item.charge,
          expectsAsync: item.command === SmbCommand.CHANGE_NOTIFY,
          encrypted: wantEncrypt,
        });
      }));
    });
    const message = segments.length === 1 ? segments[0]! : Buffer.concat(segments);
    const wire = wantEncrypt ? this.encryptor!.encrypt(message) : message;
    try { this.transport.send(makeFrame(wire)); }
    catch { this.abortConnection(new SmbProtocolError({ status: 0, message: "transport send failed" })); }
    return Promise.all(promises);
  }

  preauthDigest(): Buffer {
    return this.preauth.digest();
  }

  setVerifier(fn: (frame: Buffer, sig: Buffer) => boolean): void {
    this.verifier = fn;
  }

  setCancelSigner(fn: (msg: Buffer) => Buffer): void {
    this.signCancel = fn;
  }

  setEncryptor(e: Encryptor): void {
    this.encryptor = e;
  }

  /** When true, plaintext responses (other than SESSION_SETUP) cause a fatal protocol error. */
  setEncryptionRequired(v: boolean): void {
    this.encryptionRequired = v;
  }

  /** When true, post-handshake plaintext-unsigned responses cause a fatal protocol error. */
  setSigningRequired(v: boolean): void {
    this.signingRequired = v;
  }

  private onMessage(raw: Buffer): void {
    this.lastActivity = Date.now();
    let msg = raw;
    let wasEncrypted = false;
    if (isTransformHeader(raw)) {
      if (this.encryptor === null) {
        this.fail(new SmbProtocolError({ status: 0, message: "received encrypted frame but no encryptor installed" }));
        return;
      }
      try {
        msg = this.encryptor.decrypt(raw);
        wasEncrypted = true;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        this.fail(new SmbProtocolError({ status: 0, message: `decrypt failed: ${message}` }));
        return;
      }
    }
    // A compound response chains several SMB2 messages through NextCommand.
    let offset = 0;
    while (offset < msg.length) {
      const next = msg.length - offset >= SMB2_HEADER_SIZE ? msg.readUInt32LE(offset + 20) : 0;
      const end = next > 0 && offset + next <= msg.length ? offset + next : msg.length;
      this.handleMessage(msg.subarray(offset, end), wasEncrypted);
      if (end === msg.length || next === 0) break;
      offset = end;
    }
  }

  private handleMessage(msg: Buffer, wasEncrypted: boolean): void {
    let parsed: ReturnType<typeof decodeHeader>;
    try {
      parsed = decodeHeader(msg);
    } catch (err) {
      this.fail(new SmbProtocolError({ status: 0, message: `bad SMB2 header: ${(err as Error).message}` }));
      return;
    }
    const { header } = parsed;
    const body = Buffer.from(msg.subarray(SMB2_HEADER_SIZE));

    // MS-SMB2 §3.2.5.1.1: once Session.EncryptData is TRUE, plaintext responses
    // (other than SESSION_SETUP) must be rejected and the connection dropped.
    // This blocks an attacker — or a misbehaving server — from silently stripping
    // encryption after we agreed to use it.
    if (!wasEncrypted && this.encryptionRequired && header.command !== SmbCommand.SESSION_SETUP) {
      this.fail(new SmbProtocolError({
        status: 0,
        message: "plaintext response received but session requires encryption",
      }));
      return;
    }

    // MS-SMB2: when signing=required, every post-handshake frame must be either
    // signed (HeaderFlag.SIGNED set, signature verified above) or encrypted.
    // Pre-auth frames (NEGOTIATE, the first SESSION_SETUP) are exempt — they
    // can't be signed yet (no key) and can't be encrypted (no cipher negotiated).
    if (
      !wasEncrypted &&
      this.signingRequired &&
      header.command !== SmbCommand.NEGOTIATE &&
      header.command !== SmbCommand.SESSION_SETUP &&
      (header.flags & HeaderFlag.SIGNED) === 0 &&
      // MS-SMB2 §3.2.5.1.1: interim STATUS_PENDING responses are never signed. They carry no data;
      // the final response is still held to the signing requirement.
      !(header.status === NTStatus.STATUS_PENDING && (header.flags & HeaderFlag.ASYNC_COMMAND) !== 0)
    ) {
      this.fail(new SmbProtocolError({
        status: 0,
        message: `unsigned response received but signing is required (command ${header.command}, status 0x${(header.status >>> 0).toString(16)})`,
      }));
      return;
    }

    // Signature verification only applies to plaintext frames. Encrypted responses carry
    // their integrity guarantee in the TRANSFORM_HEADER's auth tag (already verified).
    if (!wasEncrypted && (header.flags & HeaderFlag.SIGNED) !== 0 && this.verifier !== null) {
      const working = Buffer.from(msg);
      working.fill(0, 48, 64); // zero the Signature field before computing
      const sig = header.signature ?? Buffer.alloc(16);
      if (!this.verifier(working, sig)) {
        this.fail(new SmbProtocolError({ status: 0, message: "signature verify failed" }));
        return;
      }
    }

    // Replenish credits.
    this.credits.release(header.creditRequestResponse);
    // Pre-auth hash update for NEGOTIATE/SESSION_SETUP responses.
    // Per MS-SMB2 §3.2.5.3.1 / §3.2.5.5, the preauth hash must include the
    // NEGOTIATE response and any SESSION_SETUP CHALLENGE (STATUS_MORE_PROCESSING_REQUIRED),
    // but NOT the final SESSION_SETUP SUCCESS response — the success response is signed
    // with the key that the hash is being used to derive.
    if (header.command === SmbCommand.NEGOTIATE) {
      this.preauth.update(msg);
    } else if (
      header.command === SmbCommand.SESSION_SETUP &&
      header.status === NTStatus.STATUS_MORE_PROCESSING_REQUIRED
    ) {
      this.preauth.update(msg);
    }

    const messageKey = header.messageId.toString();
    const pending = this.pendingByMessageId.get(messageKey);
    if (!pending) {
      // Could be a pure ASYNC final response keyed by AsyncId.
      if (header.asyncId !== undefined) {
        const asyncKey = header.asyncId.toString();
        const a = this.pendingByAsyncId.get(asyncKey);
        if (a) {
          this.pendingByAsyncId.delete(asyncKey);
          // Clean up the reverse mapping.
          this.asyncIdByMessageId.delete(messageKey);
          this.settle(a);
          a.resolve({ header, body });
          return;
        }
      }
      // Unsolicited; ignore.
      return;
    }

    if (isPending(header.status) && header.asyncId !== undefined) {
      // Interim response: keep the pending entry alive but key by AsyncId for the final.
      // Also record the messageId→asyncId mapping so cancel() can send the correct CANCEL frame.
      this.pendingByAsyncId.set(header.asyncId.toString(), pending);
      this.asyncIdByMessageId.set(messageKey, header.asyncId);
      this.pendingByMessageId.delete(messageKey);
      this.notePeakCredits();
      return;
    }

    this.pendingByMessageId.delete(messageKey);
    this.settle(pending);
    pending.resolve({ header, body });
  }

  private notePeakCredits(): void {
    this.peakCredits = Math.max(this.peakCredits, this.credits.available() + this.inflightCharge);
  }

  /** A request has received its final response: its credits are no longer "in flight". */
  private settle(p: PendingRequest): void {
    this.inflightCharge -= p.charge;
    this.notePeakCredits();
  }

  private onClose(): void {
    if (this.closed) return;
    this.closed = true;
    this.fail(new SmbProtocolError({ status: 0, message: "connection closed" }));
    this.emit("close");
  }

  private onError(err: Error): void {
    this.abortConnection(new SmbProtocolError({ status: 0, message: err.message, cause: err }));
  }

  private fail(err: SmbProtocolError): void {
    this.credits.fail(err);
    for (const p of this.pendingByMessageId.values()) p.reject(err);
    for (const p of this.pendingByAsyncId.values()) p.reject(err);
    this.pendingByMessageId.clear();
    this.pendingByAsyncId.clear();
    this.asyncIdByMessageId.clear();
    this.inflightCharge = 0;
  }

  cancel(opts: { messageId: bigint; asyncId?: bigint; sessionId?: bigint; treeId?: number }): void {
    if (this.closed) return;
    // If the request has been promoted to async (STATUS_PENDING received), the server
    // requires the CANCEL to carry the ASYNC_COMMAND flag and the assigned AsyncId.
    // Look up the asyncId from our tracking map if the caller did not provide one.
    const asyncId = opts.asyncId ?? this.asyncIdByMessageId.get(opts.messageId.toString());
    // Per MS-SMB2 §3.2.4.24, CANCEL inherits the integrity protection of the original
    // request: encrypted if the original was encrypted, otherwise signed.
    const pending =
      this.pendingByMessageId.get(opts.messageId.toString()) ??
      (asyncId !== undefined ? this.pendingByAsyncId.get(asyncId.toString()) : undefined);
    const encryptCancel = pending?.encrypted === true && this.encryptor !== null;
    let flags = asyncId !== undefined ? HeaderFlag.ASYNC_COMMAND : 0;
    if (!encryptCancel && this.signCancel !== null) {
      flags = flags | HeaderFlag.SIGNED;
    }
    const header = encodeHeader({
      command: SmbCommand.CANCEL,
      creditCharge: 1,
      creditRequestResponse: 0,
      flags,
      messageId: opts.messageId,
      sessionId: opts.sessionId ?? 0n,
      ...(asyncId !== undefined
        ? { asyncId }
        : { treeId: opts.treeId ?? 0 }),
      status: 0,
    });
    const body = encodeCancelRequest();
    const frameBuf = Buffer.concat([header, body]);
    if (!encryptCancel && this.signCancel !== null) {
      // Signature field (bytes 48..64) is already zeroed by encodeHeader (no signature was passed).
      // Sign over the full frame with zeroed signature, then write the result into the frame.
      const sig = this.signCancel(frameBuf);
      sig.copy(frameBuf, 48);
    }
    const wire = encryptCancel ? this.encryptor!.encrypt(frameBuf) : frameBuf;
    this.transport.send(makeFrame(wire));
  }

  private abortConnection(error: SmbProtocolError): void {
    if (this.closed) return;
    this.closed = true;
    this.fail(error);
    this.emit("close");
    this.transport.close();
  }

  close(): void {
    this.abortConnection(new SmbProtocolError({ status: 0, message: "connection closed" }));
  }
}
