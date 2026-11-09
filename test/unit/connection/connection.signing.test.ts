import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { sign } from "../../../src/connection/signing.js";
import { Dialect, HeaderFlag, SmbCommand } from "../../../src/wire/commands.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";

describe("Connection.send creditCharge", () => {
  it("passes creditCharge=0 through verbatim to the SMB2 header (no clamping to 1)", async () => {
    const ft = new FakeTransport();
    let captured: Buffer | null = null;
    ft.onSend((frame) => {
      captured = Buffer.from(frame.subarray(4)); // strip 4-byte NBSS length prefix
    });
    const conn = new Connection(ft);
    // Inject a minimal negotiated state so credits.take() isn't called for charge=0.
    const body = Buffer.alloc(36, 0); // placeholder body
    void conn.send(SmbCommand.NEGOTIATE, body, { creditCharge: 0 });
    await new Promise((r) => setImmediate(r));
    expect(captured).not.toBeNull();
    // CreditCharge is at byte offset 6 in the SMB2 header (LE uint16).
    const creditCharge = captured!.readUInt16LE(6);
    expect(creditCharge).toBe(0);
  });
});

describe("Connection.send signing", () => {
  it("zeros the signature field, computes signature over the full message, writes it back", async () => {
    const ft = new FakeTransport();
    const key = Buffer.alloc(16, 0xa5);
    let captured: Buffer | null = null;
    ft.onSend((frame) => {
      captured = Buffer.from(frame.subarray(4));
    });
    const conn = new Connection(ft);
    // Don't open(); manually inject negotiated state via test surface (added below).
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };

    const body = Buffer.from("0001", "hex"); // throwaway body
    void conn.send(SmbCommand.LOGOFF, body, {
      sessionId: 0x42n,
      signing: { sign: (m) => sign(m, key, Dialect.SMB_3_1_1) },
    });
    await new Promise((r) => setImmediate(r));
    expect(captured).not.toBeNull();
    const sentMsg = captured!;
    const sigField = Buffer.from(sentMsg.subarray(48, 64));
    // Recompute by zeroing signature
    const probe = Buffer.from(sentMsg);
    probe.fill(0, 48, 64);
    const expected = sign(probe, key, Dialect.SMB_3_1_1);
    expect(sigField).toEqual(expected);
    // SIGNED flag bit set
    const flags = sentMsg.readUInt32LE(16);
    expect(flags & 0x08).toBe(0x08);
  });
});

describe("Connection inbound enforcement — signing required", () => {
  // Build a Connection in a post-handshake state and feed it a plaintext, unsigned
  // response. With signingRequired=true, this must be rejected.

  function injectNegotiated(conn: Connection): void {
    (conn as unknown as { negotiated: unknown }).negotiated = {
      dialect: Dialect.SMB_3_1_1,
      serverGuid: Buffer.alloc(16),
      capabilities: 0,
      securityMode: 0,
      maxReadSize: 65536, maxWriteSize: 65536, maxTransactSize: 65536,
      securityBuffer: Buffer.alloc(0),
    };
  }

  function plaintextFrame(command: number, messageId: bigint): Buffer {
    const header = encodeHeader({
      command,
      creditCharge: 1,
      creditRequestResponse: 1,
      flags: 0,            // not signed
      messageId,
      sessionId: 0n,
      treeId: 0,
      status: 0,
    });
    return Buffer.concat([header, Buffer.alloc(8)]); // arbitrary body
  }

  it("rejects an unsigned, unencrypted READ response when signingRequired is true", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    injectNegotiated(conn);
    conn.setSigningRequired(true);

    const failures: unknown[] = [];
    // Send a request so there's a pending entry, then dispatch the bad response.
    const pending = conn.send(SmbCommand.READ, Buffer.alloc(0), { sessionId: 1n }).catch((e) => failures.push(e));
    await new Promise((r) => setImmediate(r));
    ft.emit("message", plaintextFrame(SmbCommand.READ, 0n));
    await pending;

    expect(failures.length).toBeGreaterThan(0);
    expect((failures[0] as Error).message).toMatch(/signing.*required|unsigned/i);
  });

  function asyncFrame(command: number, messageId: bigint, status: number): Buffer {
    const header = encodeHeader({
      command, creditCharge: 1, creditRequestResponse: 1, flags: HeaderFlag.ASYNC_COMMAND,
      messageId, asyncId: 7n, sessionId: 0n, status,
    });
    return Buffer.concat([header, Buffer.alloc(8)]);
  }

  it("accepts an unsigned interim STATUS_PENDING response but still rejects an unsigned final one", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    injectNegotiated(conn);
    conn.setSigningRequired(true);

    const failures: unknown[] = [];
    const pending = conn.send(SmbCommand.FLUSH, Buffer.alloc(0), { sessionId: 1n }).catch((e) => failures.push(e));
    await new Promise((r) => setImmediate(r));
    ft.emit("message", asyncFrame(SmbCommand.FLUSH, 0n, 0x103));
    await new Promise((r) => setImmediate(r));
    expect(failures).toHaveLength(0);
    ft.emit("message", asyncFrame(SmbCommand.FLUSH, 0n, 0));
    await pending;
    expect(failures.length).toBeGreaterThan(0);
    expect((failures[0] as Error).message).toMatch(/unsigned/i);
  });

  it("rejects an unsigned STATUS_PENDING response that is not marked async", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    injectNegotiated(conn);
    conn.setSigningRequired(true);

    const failures: unknown[] = [];
    const pending = conn.send(SmbCommand.FLUSH, Buffer.alloc(0), { sessionId: 1n }).catch((e) => failures.push(e));
    await new Promise((r) => setImmediate(r));
    const header = encodeHeader({ command: SmbCommand.FLUSH, creditCharge: 1, creditRequestResponse: 1, flags: 0, messageId: 0n, sessionId: 0n, treeId: 0, status: 0x103 });
    ft.emit("message", Buffer.concat([header, Buffer.alloc(8)]));
    await pending;
    expect(failures.length).toBeGreaterThan(0);
  });

  it("accepts a plaintext NEGOTIATE response when signingRequired is true (pre-auth exemption)", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    injectNegotiated(conn);
    conn.setSigningRequired(true);

    const pending = conn.send(SmbCommand.NEGOTIATE, Buffer.alloc(0), { creditCharge: 0 });
    await new Promise((r) => setImmediate(r));
    ft.emit("message", plaintextFrame(SmbCommand.NEGOTIATE, 0n));
    await expect(pending).resolves.toBeDefined();
  });

  it("accepts a plaintext SESSION_SETUP response when signingRequired is true (pre-auth exemption)", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    injectNegotiated(conn);
    conn.setSigningRequired(true);

    const pending = conn.send(SmbCommand.SESSION_SETUP, Buffer.alloc(0), { sessionId: 0n });
    await new Promise((r) => setImmediate(r));
    ft.emit("message", plaintextFrame(SmbCommand.SESSION_SETUP, 0n));
    await expect(pending).resolves.toBeDefined();
  });

  it("does NOT reject plaintext responses when signingRequired is the default (false)", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    injectNegotiated(conn);
    // No setSigningRequired call — default is false.

    const pending = conn.send(SmbCommand.READ, Buffer.alloc(0), { sessionId: 1n });
    await new Promise((r) => setImmediate(r));
    ft.emit("message", plaintextFrame(SmbCommand.READ, 0n));
    await expect(pending).resolves.toBeDefined();
  });

  it("does NOT reject plaintext responses after setSigningRequired(false)", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    injectNegotiated(conn);
    conn.setSigningRequired(false);

    const pending = conn.send(SmbCommand.READ, Buffer.alloc(0), { sessionId: 1n });
    await new Promise((r) => setImmediate(r));
    ft.emit("message", plaintextFrame(SmbCommand.READ, 0n));
    await expect(pending).resolves.toBeDefined();
  });
});

describe("Connection outbound — signing behavior at the wire level", () => {
  it("does NOT sign the outbound frame when no signing option is provided", async () => {
    const ft = new FakeTransport();
    let captured: Buffer | null = null;
    ft.onSend((frame) => { captured = Buffer.from(frame.subarray(4)); });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };

    // Mimic Session.makeSigning() returning undefined under "disabled" mode:
    // the caller simply omits the `signing` option.
    void conn.send(SmbCommand.READ, Buffer.alloc(8), { sessionId: 1n });
    await new Promise((r) => setImmediate(r));

    expect(captured).not.toBeNull();
    const flags = captured!.readUInt32LE(16);
    expect(flags & HeaderFlag.SIGNED).toBe(0);
    // Signature field stays zero.
    const sigSlice = captured!.subarray(48, 64);
    expect(sigSlice.every((b) => b === 0)).toBe(true);
  });

  it("signs the outbound frame when a signing function is provided", async () => {
    const ft = new FakeTransport();
    let captured: Buffer | null = null;
    ft.onSend((frame) => { captured = Buffer.from(frame.subarray(4)); });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };

    // Mimic Session.makeSigning() returning a signer under "required" or "if-offered" modes.
    // The exact signing function doesn't matter; just confirm Connection installs the flag
    // and writes a non-zero signature.
    void conn.send(SmbCommand.READ, Buffer.alloc(8), {
      sessionId: 1n,
      signing: { sign: () => Buffer.alloc(16, 0xab) },
    });
    await new Promise((r) => setImmediate(r));

    expect(captured).not.toBeNull();
    const flags = captured!.readUInt32LE(16);
    expect(flags & HeaderFlag.SIGNED).toBe(HeaderFlag.SIGNED);
    // Signature field has been written by Connection.send().
    const sigSlice = captured!.subarray(48, 64);
    expect(sigSlice.every((b) => b === 0xab)).toBe(true);
  });
});
