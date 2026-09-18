#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
environment_file="$repository_root/.env"
environment_example="$repository_root/.env.example"
default_database="$repository_root/data/information-flow.sqlite"
typescript_compiler="$repository_root/node_modules/typescript/bin/tsc"

port="${INFORMATION_FLOW_DEMO_PORT:-4173}"
install_dependencies=0

print_usage() {
  cat <<'USAGE'
Usage: ./start.sh [--port PORT] [--install]

Starts the Information Flow MVP on localhost.

Options:
  --port PORT  Use a port other than 4173.
  --install    Refresh npm dependencies before starting.
  -h, --help   Show this help text.
USAGE
}

fail() {
  printf 'Error: %s\n' "$1" >&2
  exit 1
}

while (($# > 0)); do
  case "$1" in
    --port)
      (($# >= 2)) || fail "--port requires a value."
      port="$2"
      shift 2
      ;;
    --install)
      install_dependencies=1
      shift
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    *)
      fail "Unknown option: $1"
      ;;
  esac
done

[[ "$port" =~ ^[0-9]+$ ]] || fail "Port must be an integer from 1 to 65535."
((port >= 1 && port <= 65535)) ||
  fail "Port must be an integer from 1 to 65535."

command -v node >/dev/null 2>&1 ||
  fail "Node.js 22 or newer is required."
command -v npm >/dev/null 2>&1 ||
  fail "npm is required."

node_major="$(node -p "Number(process.versions.node.split('.')[0])")"
((node_major >= 22)) ||
  fail "Node.js 22 or newer is required; found $(node --version)."

cd "$repository_root"

if [[ ! -f "$environment_file" ]]; then
  [[ ! -e "$default_database" ]] ||
    fail "The existing database needs its original INFORMATION_FLOW_DATA_KEY. Restore .env before starting."
  [[ -f "$environment_example" ]] ||
    fail "Missing .env.example; cannot create the local environment file."

  data_key="$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64url'))")"
  temporary_environment_file="$(mktemp "$repository_root/.env.tmp.XXXXXX")"
  trap 'rm -f -- "$temporary_environment_file"' EXIT

  INFORMATION_FLOW_GENERATED_KEY="$data_key" \
    node - "$environment_example" "$temporary_environment_file" <<'NODE'
const fs = require("node:fs");
const [source, target] = process.argv.slice(2);
const key = process.env.INFORMATION_FLOW_GENERATED_KEY;
let contents = fs.readFileSync(source, "utf8").replace(/\r\n/g, "\n");
if (!/^INFORMATION_FLOW_DATA_KEY=.*$/m.test(contents)) {
  throw new Error(".env.example does not define INFORMATION_FLOW_DATA_KEY");
}
contents = contents.replace(
  /^INFORMATION_FLOW_DATA_KEY=.*$/m,
  "INFORMATION_FLOW_DATA_KEY=" + key,
);
fs.writeFileSync(target, contents, { mode: 0o600 });
NODE

  mv -- "$temporary_environment_file" "$environment_file"
  chmod 600 "$environment_file"
  unset data_key temporary_environment_file
  trap - EXIT
  printf 'Created .env with a new persistent local data-encryption key.\n'
fi

node - "$environment_file" <<'NODE'
const fs = require("node:fs");
const environmentFile = process.argv[2];
const contents = fs.readFileSync(environmentFile, "utf8");
const match = /^INFORMATION_FLOW_DATA_KEY=([^\r\n]*)$/m.exec(contents);
const value = match?.[1].trim() ?? "";
let decoded;
try {
  decoded = Buffer.from(value, "base64url");
} catch {
  decoded = Buffer.alloc(0);
}
if (!/^[A-Za-z0-9_-]{43}$/.test(value) || decoded.length !== 32) {
  console.error(
    "Error: INFORMATION_FLOW_DATA_KEY in .env must be a base64url-encoded 32-byte key.",
  );
  process.exit(1);
}
NODE

administrator_credentials_updated="$(node - "$environment_file" <<'NODE'
const fs = require("node:fs");
const environmentFile = process.argv[2];
let contents = fs.readFileSync(environmentFile, "utf8").replace(/\r\n/g, "\n");

function value(name) {
  return new RegExp("^" + name + "=([^\\r\\n]*)$", "m").exec(contents)?.[1].trim();
}

function setValue(name, nextValue) {
  const expression = new RegExp("^" + name + "=.*$", "m");
  if (expression.test(contents)) {
    contents = contents.replace(expression, name + "=" + nextValue);
  } else {
    if (!contents.endsWith("\n")) contents += "\n";
    contents += name + "=" + nextValue + "\n";
  }
}

const currentUsername = value("INFORMATION_FLOW_ADMIN_USERNAME");
const currentDisplayName = value("INFORMATION_FLOW_ADMIN_DISPLAY_NAME");
const currentPassword = value("INFORMATION_FLOW_ADMIN_PASSWORD");
const isLegacyDefault = !currentUsername || currentUsername === "admin";
const needsDefaults =
  isLegacyDefault ||
  !currentDisplayName ||
  !currentPassword ||
  currentPassword === "replace-with-a-strong-local-password";
if (needsDefaults) {
  setValue("INFORMATION_FLOW_ADMIN_USERNAME", isLegacyDefault ? "manager" : currentUsername);
  setValue("INFORMATION_FLOW_ADMIN_DISPLAY_NAME", isLegacyDefault ? "Manager" : currentDisplayName || "Manager");
  setValue("INFORMATION_FLOW_ADMIN_PASSWORD", isLegacyDefault || !currentPassword || currentPassword === "replace-with-a-strong-local-password" ? "12345678" : currentPassword);
  const temporaryFile = environmentFile + ".admin.tmp." + process.pid;
  fs.writeFileSync(temporaryFile, contents, { mode: 0o600 });
  fs.renameSync(temporaryFile, environmentFile);
  fs.chmodSync(environmentFile, 0o600);
  process.stdout.write("yes");
}
NODE
)"
if [[ "$administrator_credentials_updated" == "yes" ]]; then
  printf 'Configured the default manager login in .env.\n'
fi

if ((install_dependencies == 1)) || [[ ! -f "$typescript_compiler" ]]; then
  printf 'Installing npm dependencies...\n'
  npm install --include=optional
fi

application_url="http://127.0.0.1:$port"
printf 'Starting Information Flow MVP at %s\n' "$application_url"
printf 'Press Ctrl+C to stop the server.\n'

trap 'exit 0' INT TERM
INFORMATION_FLOW_DEMO_PORT="$port" npm run demo
