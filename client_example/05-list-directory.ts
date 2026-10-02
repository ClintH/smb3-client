// Create a temp dir with three files, list names and Dirent objects, clean up.
import { loadEnv, connectClient, ensureCleanDir, removeDirRecursively } from "./_common.js";

const env = loadEnv();
const client = await connectClient(env);
const dir = `${env.share}/__node_smb3_example_listdir`;

try {
  console.log(`setting up ${dir} ...`);
  await ensureCleanDir(client, dir);

  const files = ["a.txt", "b.txt", "c.txt"];
  for (const f of files) {
    console.log(`writing ${dir}/${f} ...`);
    await client.writeFile(`${dir}/${f}`, Buffer.from(f));
  }

  // Plain name listing.
  const names = await client.readdir(dir) as string[];
  console.log("readdir (names):", names.sort());

  for (const expected of files) {
    if (!names.includes(expected)) {
      throw new Error(`missing "${expected}" in readdir result`);
    }
  }

  // Dirent listing.
  const dirents = await client.readdir(dir, { withFileTypes: true });
  console.log("readdir (withFileTypes):");
  for (const d of dirents) {
    console.log(`  ${d.name}  isFile=${d.isFile()}  isDirectory=${d.isDirectory()}  size=${d.size}  mtime=${d.mtime.toISOString()}`);
  }

  console.log("cleaning up ...");
  await removeDirRecursively(client, dir);
} finally {
  await client.close();
}

console.log("done");
