// app/e2e/run.mjs — end-to-end driver: real engine + SlopTarget fixture.
//
//   node run.mjs smoke         API-level e2e battery (no browser needed)
//   node run.mjs screenshots   regenerate docs/screenshots via the real UI
//
// Env overrides:
//   SLOP_E2E_PORT     requested engine port   (default 8791; the announce wins)
//   SLOP_E2E_TOKEN    bearer token            (default random)
//   SLOP_E2E_ENGINE   engine exe path         (default <repo>/build/src/engine/reverse-slop-engine.exe)
//   SLOP_E2E_FIXTURE  SlopTarget exe path     (default <repo>/build/src/app/SlopTarget.exe)
//   SLOP_E2E_OUT      screenshots output dir  (default <repo>/docs/screenshots)
//
// The product enforces one engine per session: if another engine (the desktop
// app, a ctest wave) is alive, ours coalesces onto it by registering our
// token; the driver then uses that endpoint and leaves it running. Engines
// with short lifetimes make the race real, so the spawn is retried and the
// port is always taken from the engine's own SLOP_ENGINE_READY announce.
import { spawn, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..", "..");
const mode = process.argv[2] ?? "smoke";

const PORT = Number(process.env.SLOP_E2E_PORT ?? 8791);
const TOKEN = process.env.SLOP_E2E_TOKEN ?? crypto.randomBytes(18).toString("hex");
const ENGINE = process.env.SLOP_E2E_ENGINE ?? path.join(repo, "build/src/engine/reverse-slop-engine.exe");
const FIXTURE = process.env.SLOP_E2E_FIXTURE ?? path.join(repo, "build/src/app/SlopTarget.exe");
const OUT = process.env.SLOP_E2E_OUT ?? path.join(repo, "docs/screenshots");

let healthPort = PORT;
let healthUrl = `http://127.0.0.1:${PORT}`;
let failures = 0;
const ok = (what, detail = "") => console.log(`PASS  ${what.padEnd(40)} ${detail}`);
const fail = (what, detail = "") => {
  failures++;
  console.error(`FAIL  ${what.padEnd(40)} ${detail}`);
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(tool, action, params = {}) {
  const r = await fetch(`${healthUrl}/api`, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ tool, action, params }),
  });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error(`http ${r.status} on ${tool}.${action}: ${body.slice(0, 200)}`);
  }
  const j = await r.json();
  if (j.ok === false) throw new Error(`${tool}.${action}: ${JSON.stringify(j.data ?? null).slice(0, 200)}`);
  return j.data;
}

const poll = async (fn, timeoutMs, stepMs = 400) => {
  const t0 = Date.now();
  for (;;) {
    try {
      const v = await fn();
      if (v) return v;
    } catch {
      // retry until the deadline
    }
    if (Date.now() - t0 > timeoutMs) throw new Error("poll timeout");
    await sleep(stepMs);
  }
};

const portOpen = (port) =>
  new Promise((resolve) => {
    const s = net.connect({ host: "localhost", port, timeout: 500 });
    s.on("connect", () => {
      s.end();
      resolve(true);
    });
    s.on("error", () => resolve(false));
    s.on("timeout", () => {
      s.destroy();
      resolve(false);
    });
  });

function killTree(pid) {
  if (pid) spawnSync("taskkill", ["/F", "/T", "/PID", String(pid)], { stdio: "ignore" });
}

function launch(cmd, args, env, cwd) {
  return spawn(cmd, args, {
    cwd,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
    env,
  });
}

// wait until the child prints a SLOP_ENGINE_READY line or dies; returns
// { announced: port|null, alive: bool, log }
async function awaitAnnounce(child, timeoutMs = 20_000) {
  let log = "";
  let announced = null;
  let dead = false;
  child.stdout.on("data", (d) => (log += d));
  child.stderr.on("data", (d) => (log += d));
  child.on("exit", () => (dead = true));
  const t0 = Date.now();
  while (!announced && !dead && Date.now() - t0 < timeoutMs) {
    const m = log.match(/SLOP_ENGINE_READY (\d+)/);
    if (m) announced = Number(m[1]);
    else await sleep(200);
  }
  return { announced, alive: !dead, log };
}

const healthAnswers = () =>
  fetch(`${healthUrl}/health`, { headers: { Authorization: `Bearer ${TOKEN}` } })
    .then((r) => r.ok)
    .catch(() => false);

let engine = null; // owned engine child, if any
let enginePid = 0;
let fixturePid = 0;
let vite = null;
let fixtureOut = "";
let vitePid = 0;

async function main() {
  for (const [label, exe] of [
    ["engine", ENGINE],
    ["fixture", FIXTURE],
  ]) {
    if (!fs.existsSync(exe)) {
      console.error(`missing ${label}: ${exe}\nbuild first: powershell -File tools/build.ps1 -NoFrontend`);
      process.exitCode = 2;
      return;
    }
  }

  // fixture first so the engine sees it in the process list
  // fixture quits on stdin EOF: keep a pipe open; it prints its value addresses
  const fixture = spawn(FIXTURE, [], { windowsHide: true, stdio: ["pipe", "pipe", "pipe"], env: process.env });
  fixture.stdout.on("data", (d) => (fixtureOut += d));
  fixturePid = fixture.pid;
  await sleep(800);

  let ready = false;
  let lastLog = "";
  for (let attempt = 1; attempt <= 3 && !ready; attempt++) {
    engine = launch(
      ENGINE,
      ["--no-onboard", "--quiet", "--port", String(PORT)],
      { ...process.env, SLOP_MCP_TOKEN: TOKEN, SLOP_MCP_PORT: String(PORT) }
    );
    enginePid = engine.pid;
    const a = await awaitAnnounce(engine);
    lastLog = a.log;

    if (a.announced) {
      // authoritative: trust the engine's own announce, not the requested port
      healthPort = a.announced;
      healthUrl = `http://127.0.0.1:${a.announced}`;
      const healthy = await poll(healthAnswers, 10_000).catch(() => false);
      if (healthy) {
        ready = true;
        if (a.alive) {
          ok("engine health", `${healthUrl} (owned)`);
        } else {
          ok("engine health", `${healthUrl} (coalesced onto an existing engine; left running)`);
        }
        break;
      }
      console.log(`attempt ${attempt}: ${healthUrl} announced but did not answer, retrying...`);
    } else {
      const why = !a.alive ? "exited without a handshake" : "stayed silent";
      console.log(`attempt ${attempt}: engine ${why}, retrying...`);
      if (a.log.trim()) console.log("  engine said: " + JSON.stringify(a.log.trim().slice(-300)));
    }

    killTree(enginePid); // ours or a stale coalesce target; best effort
    enginePid = 0;
    await sleep(3000);
  }

  if (!ready) {
    fail("engine health", "no healthy engine after 3 attempts");
    console.error(String(lastLog ?? "").slice(-2000));
    console.error("hint: a stale %LOCALAPPDATA%\\reverse-slop\\engine.json can advertise dead engines");
    return; // finally still cleans up
  }

  try {
    await run();
  } finally {
    killTree(fixturePid, "SlopTarget.exe");
    fixturePid = 0;
    if (vitePid) {
      killTree(vitePid);
      vitePid = 0;
    }
    // only shut the engine down when we own it; a coalesced foreign engine
    // keeps serving its owner
    if (enginePid) {
      await api("app", "shutdown").catch(() => {});
      await sleep(1500);
      killTree(enginePid);
      enginePid = 0;
    }
  }

  if (failures) {
    console.error(`\n${failures} failure(s)`);
    process.exitCode = 1;
  } else {
    console.log("\nall green");
  }
}

// ---- shared scenario state ------------------------------------------

let rwBase = 0n;

async function attachFixture() {
  const list = await api("target", "list");
  const proc = list.processes?.find((p) => /SlopTarget/i.test(p.name));
  if (!proc) throw new Error("SlopTarget not in target.list");
  await api("target", "attach", { pid: proc.pid });
  const regions = await api("target", "regions");
  const regs = regions.regions ?? [];
  // pick the largest committed RW region: small regions can sit next to guard
  // pages and short reads then fail with Win32 ERROR_PARTIAL_COPY (299)
  const rw =
    regs
      .filter((r) => /RW/.test(r.protect_str ?? "") && BigInt(r.size) >= 4096n)
      .sort((a, b) => Number(BigInt(b.size) - BigInt(a.size)))[0] ?? regs[1];
  rwBase = BigInt(rw.base_hex);
  ok("attach fixture", `pid ${proc.pid}, rw region ${rw.base_hex} (${rw.size} B)`);
}

const at = (off) => "0x" + (rwBase + BigInt(off)).toString(16);

// ---- smoke ------------------------------------------------------------

async function smoke() {
  await attachFixture();

  const read = await api("memory", "read", { addr: at(0), len: 16 });
  if (read.hex && read.hex.length === 32) ok("memory.read", "16 bytes");
  else fail("memory.read", JSON.stringify(read).slice(0, 120));

  await api("memory", "watch_clear").catch(() => {});
  const added = await api("memory", "watch_add", { addr: at(0x20), width: "u32", label: "e2e.probe" });
  const list = await api("memory", "watch_list");
  const hit = (list.entries ?? []).find((e) => e.label === "e2e.probe");
  if (hit) ok("watchlist roundtrip", `id ${hit.id}`);
  else fail("watchlist roundtrip", JSON.stringify(list).slice(0, 120));
  await api("memory", "watch_remove", { id: hit?.id ?? added.id }).catch(() => {});

  const ran = await api("script", "run", {
    code: 'return "e2e:" .. slop.version()',
    timeout_ms: 5000,
  });
  const text = JSON.stringify(ran);
  if (/reverse-slop/.test(text)) ok("script.run sandbox");
  else fail("script.run sandbox", text.slice(0, 120));

  await api("target", "detach").catch(() => {});
  ok("detach");
}

// ---- screenshots --------------------------------------------------------

const addrOf = (name) => {
  const m = fixtureOut.match(new RegExp(String.raw`values\.${name}:\s+(0x[0-9A-Fa-f]+)`));
  if (!m) throw new Error("fixture did not report values." + name);
  return m[1].toLowerCase();
};

async function shots() {
  await attachFixture();

  await api("memory", "watch_clear").catch(() => {});
  await api("memory", "watch_add", { addr: addrOf("health"), width: "u32", label: "player.health" });
  await api("memory", "watch_add", { addr: addrOf("speed"), width: "f32", label: "player.speed" });
  await api("memory", "watch_add", { addr: addrOf("gold"), width: "u64", label: "game.gold" });

  const cur = await api("disasm", "loaded").catch(() => null);
  if (!cur?.ready || !/SlopTarget/.test(cur.path ?? "")) {
    await api("disasm", "load", { path: FIXTURE });
  }
  await poll(async () => {
    const d = await api("disasm", "loaded");
    return d.hype?.ready || d.image?.hype?.ready ? d : null;
  }, 120_000);
  ok("image analyzed");

  // vite dev server on the engine's CORS allow-list port
  const viteBin = path.join(repo, "app/node_modules/vite/bin/vite.js");
  if (!fs.existsSync(viteBin)) {
    console.error("vite not found; run npm install in app/ first");
    process.exitCode = 2;
    return;
  }
  vite = launch(process.execPath, [viteBin], {
    ...process.env,
    VITE_SLOP_PORT: String(healthPort),
    VITE_SLOP_TOKEN: TOKEN,
  }, path.join(repo, "app"));
  vitePid = vite.pid;
  await poll(() => portOpen(1420), 30_000);
  ok("vite dev server", "http://localhost:1420");

  const require = createRequire(import.meta.url);
  let chromium;
  try {
    chromium = require("playwright-core").chromium;
  } catch {
    console.error("playwright-core not found; run npm ci in app/e2e first");
    process.exitCode = 2;
    return;
  }
  const browser = await chromium.launch({
    headless: true,
    channel: fs.existsSync("C:/Program Files/Google/Chrome/Application/chrome.exe")
      ? "chrome"
      : "msedge",
  });
  const page = await browser.newPage({
    viewport: { width: 1600, height: 900 },
    deviceScaleFactor: 1.5,
  });

  try {
    await page.goto("http://localhost:1420", { waitUntil: "networkidle" });
    await poll(async () => (await page.locator("text=waiting for the engine").count()) === 0, 90_000);
    await sleep(2500);
    // browser-only badge; not part of the shipped app
    await page.addStyleTag({ content: ".insecure-badge{display:none!important}" });

    const shot = (name) => page.screenshot({ path: path.join(OUT, `${name}.png`) });

    // never publish the real host process list: hide it before any capture
    await page.getByText("List this PC's processes instead").first().click().catch(() => {});
    await sleep(800);
    await page.getByText("hide host list").first().click().catch(() => {});
    await page.locator('input[placeholder="value"]').first().fill("1000");
    await page.getByRole("button", { name: /first/i }).first().click().catch(() => {});
    await sleep(1500);
    await shot("workspace");

    await page.keyboard.press("Control+1");
    await sleep(1200);
    await page.locator(".fn-row", { hasText: "sub_140001600" }).first().click().catch(() => {});
    await page.locator(".insn-row").first().waitFor({ timeout: 15_000 });
    await sleep(1200);
    await shot("disassembly");

    await page.keyboard.press("Control+2");
    await sleep(1500);
    await shot("strings");

    await page.keyboard.press("Control+3");
    await sleep(2000);
    await shot("memory");

    await page.keyboard.press("Control+4");
    await sleep(1200);
    await shot("debugger");

    await page.keyboard.press("Control+5");
    await sleep(1500);
    await shot("pe");

    await page.getByRole("button", { name: /scripts/i }).first().click().catch(() => {});
    await sleep(800);
    await page
      .locator("textarea")
      .first()
      .fill(
        "-- live from the attached fixture process\n" +
          'local st = slop.target.status()\n' +
          'print("backend:", st.backend, st.name, "pid", st.pid)\n' +
          "return slop.version()"
      );
    await page.keyboard.press("Control+Enter");
    await sleep(2500);
    await shot("scripts");

    await page.keyboard.press("Control+,");
    await sleep(1000);
    await shot("settings");

    await page.keyboard.press("Escape");
    await sleep(400);
    await page.keyboard.press("Control+K");
    await sleep(700);
    await shot("command-palette");
    await page.keyboard.press("Escape");

    await page.keyboard.press("Control+,");
    await sleep(700);
    const nord = page.locator("button", { hasText: /^nord/i }).first();
    if (await nord.count()) {
      await nord.click();
      await sleep(400);
    }
    await page.keyboard.press("Escape");
    await sleep(600);
    await page.keyboard.press("Control+1");
    await sleep(900);
    await page.locator(".fn-row", { hasText: "sub_140001600" }).first().click().catch(() => {});
    await page.locator(".insn-row").first().waitFor({ timeout: 15_000 });
    await sleep(1200);
    await shot("theme-nord");

    ok("10 screenshots", OUT);
  } finally {
    await browser.close().catch(() => {});
  }
}

async function run() {
  if (mode === "smoke") return smoke();
  if (mode === "screenshots") return shots();
  console.error(`unknown mode '${mode}' (smoke | screenshots)`);
  process.exitCode = 2;
}

main().then(
  () => process.exit(),
  (e) => {
    console.error(e.message ?? e);
    process.exit(1);
  }
);
