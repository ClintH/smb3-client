import { it, expect, beforeAll, afterAll } from "vitest";
import { integrationDescribe, readIntegrationEnv } from "../helpers/integrationGate.js";
import { Client } from "../../src/index.js";

integrationDescribe("integration: CRUD", () => {
  const env = readIntegrationEnv()!;
  let client: Client;
  let base: string;

  beforeAll(async () => {
    base = `${env.share}/__node_smb3_it`;
    client = new Client({
      host: env.host, port: env.port, domain: env.domain,
      username: env.username, password: env.password,
    });
    await client.connect();
    // Best-effort cleanup
    try { await client.rmdir(base); } catch { /* maybe doesn't exist */ }
    await client.mkdir(base);
  });

  afterAll(async () => {
    try { await client.rmdir(base); } catch { /* best-effort */ }
    await client?.close();
  });

  it("writeFile + readFile round-trip", async () => {
    const path = `${base}/hello.txt`;
    const content = Buffer.from("hello from node-smb3", "utf8");
    await client.writeFile(path, content);
    const got = await client.readFile(path);
    expect(got.equals(content)).toBe(true);
    await client.rm(path);
  });

  it("readdir withFileTypes returns size and times", async () => {
    const path = `${base}/meta.txt`;
    const content = Buffer.from("twelve bytes", "utf8");
    await client.writeFile(path, content);
    try {
      const entries = await client.readdir(base, { withFileTypes: true });
      const e = entries.find((d) => d.name === "meta.txt");
      expect(e).toBeDefined();
      expect(e!.size).toBe(content.length);
      expect(Math.abs(Date.now() - e!.mtime.getTime())).toBeLessThan(60_000);
      expect(Number.isNaN(e!.ctime.getTime())).toBe(false);
    } finally {
      await client.rm(path);
    }
  });

  it("readdir lists newly created files", async () => {
    await client.writeFile(`${base}/a.txt`, Buffer.from("a"));
    await client.writeFile(`${base}/b.txt`, Buffer.from("b"));
    const names = (await client.readdir(base)) as string[];
    expect(names.sort()).toEqual(["a.txt", "b.txt"]);
    await client.rm(`${base}/a.txt`);
    await client.rm(`${base}/b.txt`);
  });

  it("rename moves a file within the same share", async () => {
    const a = `${base}/r1.txt`, b = `${base}/r2.txt`;
    await client.writeFile(a, Buffer.from("x"));
    await client.rename(a, b);
    const names = (await client.readdir(base)) as string[];
    expect(names).toContain("r2.txt");
    expect(names).not.toContain("r1.txt");
    await client.rm(b);
  });

  it("rmdir removes an empty directory", async () => {
    const sub = `${base}/sub`;
    await client.mkdir(sub);
    await client.rmdir(sub);
    const names = (await client.readdir(base)) as string[];
    expect(names).not.toContain("sub");
  });
});
