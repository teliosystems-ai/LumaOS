/* Optional end-to-end browser test. Requires Chrome and Node 22+, no npm packages. */
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "luma-os-browser-"));
const inputDir = path.join(temporary, "input");
const stateDir = path.join(temporary, "state");
fs.mkdirSync(inputDir);
const sourcePath = path.join(inputDir, "invoices.csv");
fs.copyFileSync(path.join(root, "examples", "invoices.csv"), sourcePath);

const chromeCandidates = [
  process.env.CHROME_BIN,
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
].filter(Boolean);
const chromePath = chromeCandidates.find((candidate) => fs.existsSync(candidate));
const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

let serverProcess;
let browserProcess;
let browserSocket;

async function waitForText(stream, pattern, timeout = 10000) {
  return new Promise((resolve, reject) => {
    let output = "";
    const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${pattern}: ${output}`)), timeout);
    const listener = (chunk) => {
      output += chunk.toString();
      const match = output.match(pattern);
      if (match) {
        clearTimeout(timer);
        stream.off("data", listener);
        resolve(match);
      }
    };
    stream.on("data", listener);
  });
}

async function main() {
  if (!chromePath) {
    console.log("Browser integration SKIP: Chrome/Chromium was not found.");
    return;
  }

  const environment = {
    ...process.env,
    PYTHONPATH: path.join(root, "src"),
    PYTHONDONTWRITEBYTECODE: "1",
  };
  serverProcess = spawn(
    process.env.PYTHON || "python3",
    ["-u", "-m", "luma_os.cli", "serve", "--data-dir", stateDir, "--port", "0"],
    { cwd: root, env: environment, stdio: ["ignore", "pipe", "pipe"] },
  );
  const serverMatch = await waitForText(serverProcess.stdout, /http:\/\/127\.0\.0\.1:(\d+)/);
  const applicationUrl = `http://127.0.0.1:${serverMatch[1]}`;

  browserProcess = spawn(
    chromePath,
    [
      "--headless=new",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-networking",
      "--disable-component-update",
      "--remote-debugging-port=0",
      `--user-data-dir=${path.join(temporary, "chrome-profile")}`,
      "about:blank",
    ],
    { stdio: ["ignore", "ignore", "pipe"] },
  );
  const browserMatch = await waitForText(browserProcess.stderr, /DevTools listening on (ws:\/\/\S+)/);

  browserSocket = new WebSocket(browserMatch[1]);
  await new Promise((resolve, reject) => {
    browserSocket.onopen = resolve;
    browserSocket.onerror = reject;
  });
  const pending = new Map();
  let sequence = 0;
  browserSocket.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (!message.id || !pending.has(message.id)) return;
    const promise = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) promise.reject(new Error(message.error.message));
    else promise.resolve(message.result);
  };
  function call(method, params = {}, sessionId) {
    return new Promise((resolve, reject) => {
      const id = ++sequence;
      pending.set(id, { resolve, reject });
      browserSocket.send(JSON.stringify({ id, method, params, sessionId }));
    });
  }
  const { targetId } = await call("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await call("Target.attachToTarget", { targetId, flatten: true });
  const command = (method, params) => call(method, params, sessionId);
  async function evaluate(expression) {
    const result = await command("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  }
  async function waitFor(expression, label = expression) {
    for (let attempt = 0; attempt < 160; attempt += 1) {
      if (await evaluate(expression)) return;
      await delay(75);
    }
    throw new Error(`Timed out waiting for ${label}`);
  }

  await command("Page.enable");
  await command("Runtime.enable");
  await command("Emulation.setDeviceMetricsOverride", {
    width: 1440,
    height: 1000,
    deviceScaleFactor: 1,
    mobile: false,
  });
  await command("Page.navigate", { url: applicationUrl });
  await waitFor(
    `document.querySelector('#connection-pill')?.classList.contains('is-online')`,
    "online workspace",
  );

  await evaluate(`document.querySelector('[data-route="access"]').click()`);
  await evaluate(`document.querySelector('#folder-path').value=${JSON.stringify(inputDir)}; document.querySelector('#grant-form').requestSubmit()`);
  await waitFor(`document.querySelectorAll('.grant-row').length===1`, "folder enrollment");

  await evaluate(`document.querySelector('[data-route="workflow"]').click()`);
  await evaluate(`document.querySelector('#source-input').value=${JSON.stringify(sourcePath)}; document.querySelector('#workflow-form').requestSubmit()`);
  try {
    await waitFor(`!!document.querySelector('[data-run-workflow]')`, "prepared workflow");
  } catch (error) {
    const diagnostics = await evaluate(`JSON.stringify({hash:location.hash,sourceError:document.querySelector('#source-error')?.textContent,toasts:document.querySelector('#toast-region')?.innerText,detail:document.querySelector('#workflow-detail')?.innerText,body:document.body.innerText.slice(0,3000)})`);
    console.error(`Prepared-workflow diagnostics: ${diagnostics}`);
    throw error;
  }
  assert.equal(await evaluate(`document.querySelector('#artifact-summary').textContent.trim()`), "0");
  assert.match(await evaluate(`document.querySelector('#workflow-detail').innerText`), /Ready/);

  await evaluate(`document.querySelector('[data-run-workflow]').click()`);
  await waitFor(`document.querySelector('#artifact-summary').textContent.trim()==='2'`, "committed artifacts");
  assert.match(await evaluate(`document.querySelector('#workflow-detail').innerText`), /Completed/);

  await evaluate(`document.querySelector('[data-route="artifacts"]').click(); document.querySelector('[data-select-artifact]').click()`);
  await waitFor(
    `!document.querySelector('.artifact-content').textContent.includes('Loading artifact content')`,
    "artifact content",
  );
  const artifactText = await evaluate(`document.querySelector('.artifact-content').textContent`);
  assert.match(artifactText, /(Invoice report|month,currency,invoice_count,total)/);

  await evaluate(`document.querySelector('[data-route="activity"]').click()`);
  assert.ok(await evaluate(`document.querySelectorAll('.activity-row').length>=2`));

  await command("Page.reload", {});
  await waitFor(`document.querySelector('#artifact-summary')?.textContent.trim()==='2'`, "reload persistence");
  await command("Emulation.setDeviceMetricsOverride", {
    width: 390,
    height: 844,
    deviceScaleFactor: 1,
    mobile: true,
  });
  await delay(150);
  assert.ok(await evaluate(`document.documentElement.scrollWidth<=innerWidth+1`), "workspace fits a 390px viewport");
  const screenshot = await command("Page.captureScreenshot", { format: "png" });
  const screenshotPath = path.join(temporary, "luma-os-mvp.png");
  fs.writeFileSync(screenshotPath, Buffer.from(screenshot.data, "base64"));

  console.log("Browser integration PASS: enroll, prepare without autorun, explicit run, artifacts, receipts, reload, mobile.");
  console.log(`Screenshot: ${screenshotPath}`);
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    if (browserSocket) browserSocket.close();
    if (browserProcess) browserProcess.kill("SIGTERM");
    if (serverProcess) serverProcess.kill("SIGTERM");
  });
