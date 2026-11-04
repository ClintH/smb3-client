import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Open } from "../../../src/open/open.js";
import { Tree } from "../../../src/tree/tree.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { Writer } from "../../../src/wire/buffer.js";
import { Capability, Dialect, SmbCommand } from "../../../src/wire/commands.js";
import { readAll } from "../../../src/open/read.js";
import { writeAll } from "../../../src/open/write.js";
import { mapConcurrent, planRanges } from "../../../src/open/pool.js";

interface Seen { command: number; messageId: bigint; charge: number; requested: number; length: number }

function respHeader(command: number, req: Buffer, grant: number): Buffer {
  return encodeHeader({
    command, creditCharge: req.readUInt16LE(6), creditRequestResponse: grant, flags: 0x1,
    messageId: req.readBigUInt64LE(24), sessionId: 0xabcdn, treeId: 0x42, status: 0,
  });
}

function setup(opts: { grant: number; maxIo: number; capabilities: number }) {
  const ft = new FakeTransport();
  const seen: Seen[] = [];
  ft.onSend((frame) => {
    const smb = frame.subarray(4);
    const command = smb.readUInt16LE(12);
    const length = smb.readUInt32LE(64 + 4);
    seen.push({ command, messageId: smb.readBigUInt64LE(24), charge: smb.readUInt16LE(6), requested: smb.readUInt16LE(14), length });
    if (command === SmbCommand.READ) {
      const w = new Writer();
      w.u16(17); w.u8(80); w.u8(0); w.u32(length); w.u32(0); w.u32(0); w.bytes(Buffer.alloc(length, 1));
      ft.deliver(Buffer.concat([respHeader(command, smb, opts.grant), w.buffer()]));
    } else if (command === SmbCommand.WRITE) {
      const w = new Writer();
      w.u16(17); w.u16(0); w.u32(length); w.u32(0); w.u16(0); w.u16(0);
      ft.deliver(Buffer.concat([respHeader(command, smb, opts.grant), w.buffer()]));
    }
  });
  const conn = new Connection(ft);
  (conn as unknown as { negotiated: unknown }).negotiated = {
    dialect: Dialect.SMB_3_1_1, capabilities: opts.capabilities, maxReadSize: opts.maxIo, maxWriteSize: opts.maxIo,
  };
  const tree = Object.assign(Object.create(Tree.prototype), {
    conn, session: { sessionId: 0xabcdn, makeSigning: () => undefined },
    treeId: 0x42, shareType: "disk", path: "x", maximalAccess: 0,
  }) as Tree;
  const open = new (Open as unknown as { new (...a: unknown[]): Open })(tree, Buffer.alloc(16, 0xfe), {} as never);
  return { conn, open, seen };
}

const MiB = 1 << 20;

describe("large I/O", () => {
  it("starts single-credit and grows once the server has granted credits", async () => {
    const { open, seen } = setup({ grant: 64, maxIo: 8 * MiB, capabilities: Capability.LARGE_MTU });
    await readAll(open, 10n); // first exchange: only 1 credit owned, so a single-credit request
    expect(seen[0]!.charge).toBe(1);
    expect(seen[0]!.requested).toBeGreaterThan(1);
    await readAll(open, BigInt(MiB)); // the grant has arrived: now multi-credit
    expect(seen.slice(1).some((s) => s.charge > 1)).toBe(true);
  });

  it("never exceeds the credits granted, even if the server allows more", async () => {
    const { open, seen } = setup({ grant: 1, maxIo: 8 * MiB, capabilities: Capability.LARGE_MTU });
    await readAll(open, BigInt(MiB));
    expect(seen.every((s) => s.charge === 1)).toBe(true);
    expect(seen.length).toBe(16);
  });

  it("uses 64 KiB when the server lacks LARGE_MTU", async () => {
    const { open, seen } = setup({ grant: 64, maxIo: 8 * MiB, capabilities: 0 });
    await readAll(open, BigInt(MiB));
    expect(seen.every((s) => s.length <= 65536 && s.charge === 1)).toBe(true);
  });

  it("charges ceil(len/64KiB) credits, consumes that many message IDs, and requests a window", async () => {
    const { open, seen } = setup({ grant: 64, maxIo: 8 * MiB, capabilities: Capability.LARGE_MTU });
    await writeAll(open, 0n, Buffer.alloc(1)); // warm up: lets the server grant 64 credits
    await writeAll(open, 0n, Buffer.alloc(4 * MiB, 7));
    const big = seen.filter((s) => s.charge > 1);
    expect(big.length).toBeGreaterThan(0);
    for (const s of big) expect(s.charge).toBe(Math.ceil(s.length / 65536));
    expect(seen[0]!.requested).toBeGreaterThan(1);
    // Message IDs advance by the charge of the previous request.
    for (let i = 1; i < seen.length; i++) {
      expect(seen[i]!.messageId).toBe(seen[i - 1]!.messageId + BigInt(Math.max(1, seen[i - 1]!.charge)));
    }
    expect(seen.reduce((n, s) => n + s.length, 0)).toBe(4 * MiB + 1);
  });

  it("honours a server maxReadSize below 64 KiB", async () => {
    const { open, seen } = setup({ grant: 1, maxIo: 100, capabilities: Capability.LARGE_MTU });
    const out = await readAll(open, 250n);
    expect(out.length).toBe(250);
    expect(seen.map((s) => s.length)).toEqual([100, 100, 50]);
  });
});

describe("pool", () => {
  it("planRanges covers the span exactly", () => {
    expect(planRanges(10n, 250n, 100)).toEqual([
      { offset: 10n, length: 100 }, { offset: 110n, length: 100 }, { offset: 210n, length: 50 },
    ]);
    expect(planRanges(0n, 0n, 100)).toEqual([]);
  });

  it("mapConcurrent preserves order, bounds concurrency and stops after a failure", async () => {
    let active = 0, peak = 0;
    const out = await mapConcurrent([1, 2, 3, 4, 5, 6], 2, async (n) => {
      peak = Math.max(peak, ++active);
      await new Promise((r) => setTimeout(r, 1));
      active--;
      return n * 2;
    });
    expect(out).toEqual([2, 4, 6, 8, 10, 12]);
    expect(peak).toBe(2);

    let started = 0;
    await expect(mapConcurrent([1, 2, 3, 4, 5, 6], 1, async (n) => {
      started++;
      if (n === 2) throw new Error("boom");
      return n;
    })).rejects.toThrow("boom");
    expect(started).toBe(2);
  });
});
