import { expect, test } from '@playwright/test';

test('tool indicator: pending then resolved with latency', async ({ page }) => {
  await page.goto('/');

  const input = page.locator('.chat-input textarea');
  await expect(input).toBeEnabled({ timeout: 10_000 });

  await input.fill('what is the gdpr training status of mario rossi?');
  await page.locator('.send').click();

  // While the mock is still streaming, the chip is pending
  const tool = page.locator('.tool-chip').first();
  await expect(tool).toBeVisible({ timeout: 5_000 });
  await expect(tool).toContainText('postgres.query');

  // Eventually it resolves with the latency badge
  await expect(page.locator('.tool-chip-done')).toBeVisible({ timeout: 10_000 });
  await expect(page.locator('.tool-chip-done .tool-latency')).toContainText(/\d+\s*ms/);
});
