import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  use: { baseURL: "http://127.0.0.1:8001", headless: true },
  workers: 1,
  webServer: {
    command:
      "../.venv/bin/uvicorn agentzero.app:create_app --factory --app-dir .. --host 127.0.0.1 --port 8001",
    url: "http://127.0.0.1:8001/api/health",
    timeout: 20000,
    reuseExistingServer: false,
    env: { AGENTZERO_DATA_DIR: "/tmp/agentzero-browser-tests" },
  },
});
