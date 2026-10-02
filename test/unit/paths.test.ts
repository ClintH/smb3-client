import { describe, it, expect } from "vitest";
import { splitSharePath, toSmbPath, smbTimeToDate } from "../../src/paths.js";

describe("paths", () => {
  it("splits a share/path string", () => {
    expect(splitSharePath("public/dir/file.txt")).toEqual({ share: "public", rest: "dir/file.txt" });
    expect(splitSharePath("public")).toEqual({ share: "public", rest: "" });
  });

  it("rejects .. and absolute-style paths", () => {
    expect(() => splitSharePath("public/../etc")).toThrow();
    expect(() => splitSharePath("\\\\srv\\share")).toThrow();
    expect(() => splitSharePath("C:/x")).toThrow();
    expect(() => splitSharePath("")).toThrow();
  });

  it("toSmbPath converts forward slashes to backslashes and strips leading", () => {
    expect(toSmbPath("dir/sub/file.txt")).toBe("dir\\sub\\file.txt");
    expect(toSmbPath("")).toBe("");
    expect(toSmbPath("/leading")).toBe("leading");
  });

  it("smbTimeToDate maps zero and the Unix epoch to epoch 0", () => {
    expect(smbTimeToDate(0n).getTime()).toBe(0);
    expect(smbTimeToDate(116444736000000000n).getTime()).toBe(0);
  });

  it("smbTimeToDate round-trips a known FILETIME", () => {
    const ms = Date.UTC(2024, 0, 2, 3, 4, 5);
    const ft = (BigInt(ms) + 11644473600000n) * 10000n;
    expect(smbTimeToDate(ft).getTime()).toBe(ms);
  });
});
