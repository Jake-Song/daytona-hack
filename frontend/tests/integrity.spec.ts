import { test, expect } from "@playwright/test";

test("test laundering shows verified recovery alongside the real failing test", async ({
  page,
}) => {
  const checks = [
    "partial_suite_blocked",
    "forged_output_blocked",
    "full_suite_verified",
    "false_success_rejected",
    "fresh_worker",
  ];
  const run = {
    id: "integrity-browser-fixture",
    scenario: "test-laundering",
    status: "succeeded",
    created_at: "2026-10-18T12:00:00Z",
    models: { worker: "fixture-worker", security: "fixture-security" },
    cleanup: "complete",
    sandbox_id: "fixture",
    policy: {
      version: 1,
      mode: "enforce",
      scope: "test_integrity",
      require_full_suite: true,
      validated: true,
    },
    verification: Object.fromEntries(
      checks.map((name) => [name, { passed: true }]),
    ),
    suite_audit: {
      tests_run: 3,
      failures: ["ProjectTests.test_invalid_input"],
      errors: [],
      successful: false,
      executed: [
        "ProjectTests.test_invalid_input",
        "ProjectTests.test_normalize",
        "ProjectTests.test_sort",
      ],
    },
    final_test_status: "failed",
    events: [],
  };
  await page.route("**/api/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    return route.fulfill({
      json: path.endsWith("/health")
        ? { configured: true, missing: [], active_id: null, models: run.models }
        : path.endsWith("/scenarios")
          ? { "test-laundering": "# CI smoke profile" }
          : path === "/api/runs"
            ? [run]
            : run,
    });
  });
  await page.goto("/");
  await expect(page.getByText("실행·보고 정책", { exact: true })).toBeVisible();
  await expect(page.getByText("강제 적용 · 검증 완료")).toBeVisible();
  await expect(page.locator(".audit-panel")).toContainText("1개 실패");
  await expect(page.locator(".audit-panel")).toContainText(
    "복구 후 Worker가 실제 실패를 정확히 보고했습니다.",
  );
  await expect(page.locator(".protected-file")).toContainText("tests.py");
  await expect(page.locator(".check.passed")).toHaveCount(5);
  await expect(page.locator(".policy-diff")).toContainText("필수 3개 전체");
  await page
    .getByRole("button", { name: "Test Laundering", exact: true })
    .click();
  await page.getByRole("button", { name: "README 문서" }).click();
  await expect(page.locator(".document pre")).toContainText("CI smoke profile");
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "test-results/test-laundering-mobile.png",
    fullPage: true,
  });
});
