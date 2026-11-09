import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { CreditWindow } from "../../../src/connection/credits.js";
import { Connection } from "../../../src/connection/connection.js";
import { createByteBudget } from "../../../src/connection/byteBudget.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { Dialect, HeaderFlag, SmbCommand } from "../../../src/wire/commands.js";

interface Seg { command: number; flags: number; messageId: bigint; next: number; length: number; sig: Buffer }

function parse(frame: Buffer): Seg[] {
  const smb = frame.subarray(4);
  const out: Seg[] = [];
  let off = 0;
  for (;;) {
    const next = smb.readUInt32LE(off + 20);
    out.push({
      command: smb.readUInt16LE(off + 12), flags: smb.readUInt32LE(off + 16), messageId: smb.readBigUInt64LE(off + 24),
      next, length: next || smb.length - off, sig: Buffer.from(smb.subarray(off + 48, off + 64)),
    });
    if (!next) return out;
    off += next;
  }
}

function resp(seg: Seg, hasNext: boolean, payload = Buffer.from([9, 0, 0, 0])): Buffer {
  const raw = 64 + payload.length;
  const len = hasNext ? Math.ceil(raw / 8) * 8 : raw;
  const hdr = encodeHeader({
    command: seg.command, creditCharge: 1, creditRequestResponse: 32, flags: HeaderFlag.SERVER_TO_REDIR | (hasNext ? 0 : 0),
    messageId: seg.messageId, sessionId: 1n, treeId: 2, status: 0, ...(hasNext ? { nextCommand: len } : {}),
  });
  return Buffer.concat([hdr, payload, Buffer.alloc(len - raw)]);
}

function setup(timeout?: number, credits = 64) {
  const ft = new FakeTransport();
  const conn = new Connection(ft, timeout ? { requestTimeoutMs: timeout } : {});
  Object.assign(conn, { credits: new CreditWindow(credits), peakCredits: credits });
  (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
  return { ft, conn };
}

const items = [
  { command: SmbCommand.CREATE, body: Buffer.alloc(5, 1) },
  { command: SmbCommand.READ, body: Buffer.alloc(7, 2) },
  { command: SmbCommand.CLOSE, body: Buffer.alloc(24, 3) },
];

describe("compound requests", () => {
  it("chains commands with padding, NextCommand, related flags and consecutive message IDs", async () => {
    const { ft, conn } = setup();
    let segs: Seg[] = [];
    ft.onSend((frame) => {
      segs = parse(frame);
      const frames = segs.map((s, i) => resp(s, i < segs.length - 1));
      ft.deliver(Buffer.concat(frames)); // one compound response
    });
    const out = await conn.sendCompound(items, { sessionId: 1n, treeId: 2 });
    expect(segs.map((s) => s.command)).toEqual([SmbCommand.CREATE, SmbCommand.READ, SmbCommand.CLOSE]);
    expect(segs.map((s) => (s.flags & HeaderFlag.RELATED_OPERATIONS) !== 0)).toEqual([false, true, true]);
    expect(segs[0]!.next % 8).toBe(0);
    expect(segs[0]!.next).toBe(72); expect(segs[1]!.next).toBe(72); expect(segs[2]!.next).toBe(0);
    expect(segs.map((s) => s.messageId)).toEqual([segs[0]!.messageId, segs[0]!.messageId + 1n, segs[0]!.messageId + 2n]);
    expect(out.map((r) => r.header.command)).toEqual([SmbCommand.CREATE, SmbCommand.READ, SmbCommand.CLOSE]);
  });

  it("matches responses that arrive as separate frames in any order", async () => {
    const { ft, conn } = setup();
    ft.onSend((frame) => {
      const segs = parse(frame);
      for (const s of [...segs].reverse()) ft.deliver(resp(s, false));
    });
    const out = await conn.sendCompound(items, { sessionId: 1n, treeId: 2 });
    expect(out.map((r) => r.header.command)).toEqual([SmbCommand.CREATE, SmbCommand.READ, SmbCommand.CLOSE]);
  });

  it("signs each command separately over its padded segment", async () => {
    const { ft, conn } = setup();
    const signed: number[] = [];
    ft.onSend((frame) => {
      const segs = parse(frame);
      expect(segs.every((s) => (s.flags & HeaderFlag.SIGNED) !== 0 && s.sig.equals(Buffer.alloc(16, 0xaa)))).toBe(true);
      segs.forEach((s, i) => ft.deliver(resp(s, false)) && i);
    });
    const signing = { sign: (m: Buffer) => { signed.push(m.length); return Buffer.alloc(16, 0xaa); } };
    await conn.sendCompound(items, { sessionId: 1n, treeId: 2, signing });
    expect(signed).toEqual([72, 72, 88]);
  });

  it("reports whether the granted credits can cover a compound", () => {
    const { conn } = setup(undefined, 2);
    expect(conn.canCompound(2)).toBe(true);
    expect(conn.canCompound(3)).toBe(false);
  });
});

describe("idle watchdog", () => {
  it("aborts when nothing arrives, naming the wait and outstanding count", async () => {
    const { conn } = setup(40, 1);
    await expect(conn.send(SmbCommand.ECHO, Buffer.alloc(4), {})).rejects.toMatchObject({
      code: "ETIMEDOUT", message: expect.stringMatching(/nothing received for \d+ ms with 1 request\(s\) outstanding/),
    });
  });

  it("tolerates a slow server that keeps sending, however long the request takes", async () => {
    const { ft, conn } = setup(60, 1);
    let last: Seg | undefined;
    ft.onSend((frame) => { last = parse(frame)[0]; });
    const done = conn.send(SmbCommand.ECHO, Buffer.alloc(4), {});
    // Unrelated traffic (another request's response) shows the server is alive.
    for (let i = 1; i <= 4; i++) setTimeout(() => ft.deliver(resp({ ...last!, messageId: 99n + BigInt(i) }, false)), i * 30);
    setTimeout(() => ft.deliver(resp(last!, false)), 150);
    await expect(done).resolves.toBeDefined();
  });
});

describe("byte budget", () => {
  it("bounds bytes in flight, admits in order, and lets an oversized request run alone", async () => {
    const budget = createByteBudget(100);
    let active = 0, peak = 0;
    const order: number[] = [];
    const task = (n: number, bytes: number) => budget.run(bytes, async () => {
      order.push(n); active += bytes; peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 5));
      active -= bytes;
    });
    await Promise.all([task(1, 60), task(2, 60), task(3, 30), task(4, 500), task(5, 10)]);
    expect(order).toEqual([1, 2, 3, 4, 5]);
    expect(peak).toBe(500);
    expect(active).toBe(0);
  });
});
