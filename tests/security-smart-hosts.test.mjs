import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

const temp = await fs.mkdtemp(path.join(os.tmpdir(), "hyrovi-smart-hosts-"));
process.env.HYROVI_SMART_HOSTS_FILE = path.join(temp, "smart.json");
const {default:smart} = await import("../backend/internal/security_smart_hosts.js");
test("initial selection contains only Stoneapp", async () => {
  assert.deepEqual(await smart.list(), ["stoneapp.hyrovi.com"]);
});
test("a configured host can be added and is idempotent", async () => {
  await smart.change("AI.HYROVI.COM", true, ["ai.hyrovi.com"]);
  await smart.change("ai.hyrovi.com", true, ["ai.hyrovi.com"]);
  assert.deepEqual(await smart.list(), ["stoneapp.hyrovi.com", "ai.hyrovi.com"]);
});
test("unknown, sensitive and invalid hosts are rejected", async () => {
  assert.throws(() => smart.change("unknown.hyrovi.com",true,["ai.hyrovi.com"]));
  assert.throws(() => smart.change("hpm.hyrovi.com",true,["hpm.hyrovi.com"]));
  assert.throws(() => smart.change("tests.hyrovi.com",true,["tests.hyrovi.com"]));
  assert.throws(() => smart.change("../etc/passwd",true,["../etc/passwd"]));
});
test("removing Stoneapp remains removed after reading persisted config", async () => {
  await smart.change("stoneapp.hyrovi.com", false);
  assert.deepEqual(await smart.list(), ["ai.hyrovi.com"]);
  await smart.change("ai.hyrovi.com", false);
  assert.deepEqual(await smart.list(), []);
  const raw = JSON.parse(await fs.readFile(process.env.HYROVI_SMART_HOSTS_FILE, "utf8"));
  assert.deepEqual(raw.hosts, []);
  const stat = await fs.stat(process.env.HYROVI_SMART_HOSTS_FILE);
  assert.equal(stat.mode & 0o777, 0o600);
});
test("cleanup", async () => {
  await fs.rm(temp,{force:true,recursive:true});
});
