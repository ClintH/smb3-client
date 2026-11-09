import { createCipheriv, createHmac, timingSafeEqual } from "node:crypto";
import { Dialect } from "../wire/commands.js";

export function hmacSha256(key: Buffer, data: Buffer): Buffer {
  return createHmac("sha256", key).update(data).digest();
}

function aesEcbEncryptBlock(key: Buffer, block: Buffer): Buffer {
  const c = createCipheriv("aes-128-ecb", key, null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(block), c.final()]);
}

function leftShift(b: Buffer): Buffer {
  const out = Buffer.alloc(b.length);
  let carry: number = 0;
  for (let i = b.length - 1; i >= 0; i--) {
    const v = b[i]!;
    out[i] = ((v << 1) & 0xff) | carry;
    carry = (v & 0x80) !== 0 ? 1 : 0;
  }
  return out;
}

function deriveSubkeys(key: Buffer): { k1: Buffer; k2: Buffer } {
  const Rb = Buffer.alloc(16);
  Rb[15] = 0x87;
  const L = aesEcbEncryptBlock(key, Buffer.alloc(16));
  const k1 = leftShift(L);
  if (L[0]! & 0x80) for (let i = 0; i < 16; i++) k1[i] = k1[i]! ^ Rb[i]!;
  const k2 = leftShift(k1);
  if (k1[0]! & 0x80) for (let i = 0; i < 16; i++) k2[i] = k2[i]! ^ Rb[i]!;
  return { k1, k2 };
}

export function aesCmac(key: Buffer, msg: Buffer): Buffer {
  if (key.length !== 16) throw new Error("AES-CMAC: 16-byte key required");
  const { k1, k2 } = deriveSubkeys(key);
  const blocks = Math.ceil(msg.length / 16);
  const lastFull = blocks > 0 && msg.length % 16 === 0;
  const nBlocks = Math.max(blocks, 1);

  let lastBlock: Buffer;
  if (lastFull) {
    lastBlock = Buffer.from(msg.subarray((nBlocks - 1) * 16, nBlocks * 16));
    for (let i = 0; i < 16; i++) lastBlock[i] = lastBlock[i]! ^ k1[i]!;
  } else {
    const start = (nBlocks - 1) * 16;
    const tail = msg.subarray(start);
    lastBlock = Buffer.alloc(16);
    tail.copy(lastBlock, 0);
    lastBlock[tail.length] = 0x80;
    for (let i = 0; i < 16; i++) lastBlock[i] = lastBlock[i]! ^ k2[i]!;
  }

  // CBC with a zero IV over all but the last block is the CMAC chain; one native call instead of one per block.
  let X: Buffer = Buffer.alloc(16);
  if (nBlocks > 1) {
    const c = createCipheriv("aes-128-cbc", key, Buffer.alloc(16));
    c.setAutoPadding(false);
    const out = c.update(msg.subarray(0, (nBlocks - 1) * 16));
    X = out.subarray(out.length - 16);
  }
  const Y = Buffer.alloc(16);
  for (let j = 0; j < 16; j++) Y[j] = X[j]! ^ lastBlock[j]!;
  return aesEcbEncryptBlock(key, Y);
}

export function sign(msg: Buffer, key: Buffer, dialect: number): Buffer {
  if (dialect === Dialect.SMB_2_0_2 || dialect === Dialect.SMB_2_1_0) {
    return hmacSha256(key, msg).subarray(0, 16);
  }
  return aesCmac(key, msg);
}

export function verify(msg: Buffer, sig: Buffer, key: Buffer, dialect: number): boolean {
  const expected = sign(msg, key, dialect);
  if (sig.length !== expected.length) return false;
  return timingSafeEqual(sig, expected);
}
