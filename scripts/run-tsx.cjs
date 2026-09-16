const { spawnSync } = require("node:child_process");
const { resolve } = require("node:path");

const tsxCli = require.resolve("tsx/cli");
const shimPath = resolve(__dirname, "tsx-windows-user-shim.cjs").replaceAll(
  "\\",
  "/",
);
const preloadOption = `--require="${shimPath}"`;
const inheritedOptions = process.env.NODE_OPTIONS?.trim();
const nodeOptions = inheritedOptions
  ? `${inheritedOptions} ${preloadOption}`
  : preloadOption;

const result = spawnSync(process.execPath, [tsxCli, ...process.argv.slice(2)], {
  env: { ...process.env, NODE_OPTIONS: nodeOptions },
  stdio: "inherit",
});

if (result.error !== undefined) throw result.error;
process.exitCode = result.status ?? 1;
