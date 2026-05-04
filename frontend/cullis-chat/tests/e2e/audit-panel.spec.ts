import { expect, test } from '@playwright/test';

test('audit panel: row populated with trace_id + latency + principal', async ({ page }) => {
  await page.goto('/');

  // Empty state
  await expect(page.locator('.ap-empty')).toBeVisible();

  const input = page.locator('.chat-input textarea');
  await expect(input).toBeEnabled({ timeout: 10_000 });

  await input.fill('list active sessions across the org.');
  await page.locator('.send').click();

  // Wait for the assistant turn to land + audit row to appear.
  const entry = page.locator('.audit-entry').first();
  await expect(entry).toBeVisible({ timeout: 15_000 });

  // Latency cell present and numeric
  await expect(entry).toContainText(/\d+\s*ms/);

  // Principal cell carries the ADR-020 shape (italic em + name)
  await expect(entry.locator('.ae-principal em')).toContainText('user');
  await expect(entry.locator('.ae-principal')).toContainText('mario');

  // Trace id is a non-empty token-looking string
  const trace = await entry.locator('.ae-trace').innerText();
  expect(trace).toMatch(/^t_[a-z0-9]+/);

  // Click → cross-highlight on the matching message body
  await entry.click();
  await expect(page.locator('.msg-selected')).toBeVisible();
});
