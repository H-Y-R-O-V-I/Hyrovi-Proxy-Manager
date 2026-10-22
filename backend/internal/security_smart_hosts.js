import fs from "node:fs/promises";
import path from "node:path";
export class SmartHostValidationError extends Error {
  constructor(message) {super(message);this.name="SmartHostValidationError";}
}

// HPM-only selection of hosts shown by Smart Analytics. Existing proxy
// logging and consent-controlled website telemetry remain unchanged.
const FILE = process.env.HYROVI_SMART_HOSTS_FILE ||
  "/data/nginx/hyrovi-security/smart-analytics-hosts.json";
const DEFAULT_HOST = "stoneapp.hyrovi.com";
const DOMAIN = /^(?=.{4,253}$)(?!-)[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;
let pending = Promise.resolve();

const validate = (input) => {
  const host = String(input ?? "").trim().toLowerCase();
  if (!DOMAIN.test(host) || host.includes("..") || host.endsWith(".") ||
      host.split(".").some(part => part.startsWith("-") || part.endsWith("-")) ||
      host === "tests.hyrovi.com" || host === "hpm.hyrovi.com") {
    throw new SmartHostValidationError("Ungültiger oder geschützter Host");
  }
  return host;
};

async function read() {
  try {
    const stat = await fs.stat(FILE);
    if (stat.size > 16_384) throw new SmartHostValidationError("Invalid Smart host config size");
    const stored = JSON.parse(await fs.readFile(FILE, "utf8"));
    if (stored?.version !== 1 || !Array.isArray(stored.hosts)) throw new Error("Invalid config");
    return [...new Set(stored.hosts.filter(host => typeof host === "string")
      .map(host => { try { return validate(host); } catch { return null; } })
      .filter(Boolean))].slice(0, 25);
  } catch (e) {
    if (e.code === "ENOENT") return [DEFAULT_HOST];
    throw e;
  }
}
async function write(hosts) {
  await fs.mkdir(path.dirname(FILE), {recursive: true});
  const temporary = FILE + "." + process.pid + ".tmp";
  try {
    await fs.writeFile(temporary, JSON.stringify({version:1, hosts},null,2) + "\n",
      {mode:0o600,flag:"w"});
    await fs.rename(temporary, FILE);
  } finally {
    await fs.rm(temporary,{force:true}).catch(() => {});
  }
}
const list = () => read();
function change(host, enabled, availableHosts = []) {
  const normalized = validate(host);
  if (enabled && !availableHosts.includes(normalized)) {
    throw new SmartHostValidationError("Host ist in HPM nicht als verwalteter Proxy-Host verfügbar");
  }
  const op = pending.then(async () => {
    const hosts = await read();
    const result = enabled
      ? [...new Set([...hosts, normalized])].slice(0,25)
      : hosts.filter(h => h !== normalized);
    if (enabled && hosts.length >= 25 && !hosts.includes(normalized)) {
      throw new SmartHostValidationError("Maximum von 25 Smart-Hosts erreicht");
    }
    await write(result);
    return {hosts:result};
  });
  pending = op.catch(() => {});
  return op;
}
export default {list,change,validate};
