import { expect, test } from '@playwright/test';

test('chat happy path: empty state → send → streamed assistant answer', async ({ page }) => {
  await page.goto('/');

  // Empty state visible
  await expect(page.getByText(/Ask\s+anything/i)).toBeVisible();
  await expect(page.locator('.chat-empty-hints .hint').first()).toBeVisible();

  // Type a question and send. (Don't click the hint — that's its own test.)
  const input = page.locator('.chat-input textarea');
  await expect(input).toBeEnabled({ timeout: 10_000 });
  await input.fill('ciao');
  await page.locator('.send').click();

  // User message appears immediately
  await expect(page.locator('.msg-user').last()).toContainText('ciao');

  // Assistant message arrives, with non-empty content
  const assistantBody = page.locator('.msg-assistant .msg-body-assistant').last();
  await expect(assistantBody).toBeVisible({ timeout: 15_000 });
  await expect(assistantBody).toContainText('Cullis Chat', { timeout: 15_000 });

  // The streaming caret should disappear once pending=false
  await expect(page.locator('.markdown-body.is-pending')).toHaveCount(0, { timeout: 15_000 });
});
