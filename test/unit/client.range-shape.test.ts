import { describe, it, expect } from "vitest";
import { Client } from "../../src/client.js";

describe("Client.readRange/writeRange", () => {
  const c = new Client({ host: "x", username: "u", password: "p" });

  it("are functions", () => {
    expect(typeof c.readRange).toBe("function");
    expect(typeof c.writeRange).toBe("function");
  });

  it("reject negative or non-integer offsets before touching the network", async () => {
    await expect(c.readRange("share/a", -1, 4)).rejects.toThrow(RangeError);
    await expect(c.readRange("share/a", 0, 1.5)).rejects.toThrow(RangeError);
    await expect(c.writeRange("share/a", -1, Buffer.from("x"))).rejects.toThrow(RangeError);
  });

  it("readRange of zero bytes is empty without a connection", async () => {
    await expect(c.readRange("share/a", 10, 0)).resolves.toHaveLength(0);
  });
});
