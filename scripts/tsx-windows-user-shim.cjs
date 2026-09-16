// tsx uses process.geteuid() only to derive a temporary cache directory name.
// On Windows, Node can instead call os.userInfo(), which may fail before tests
// start even when system memory is available. Keep this fallback test-only.
if (process.platform === "win32" && typeof process.geteuid !== "function") {
  Object.defineProperty(process, "geteuid", {
    configurable: true,
    value: () => 0,
  });
}
