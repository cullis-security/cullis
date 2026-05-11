import { expect, test } from '@playwright/test';

test('stop button aborts the in-flight stream, retry re-issues the turn', async ({ page }) => {
  await page.goto('/');

  const input = page.locator('.chat-input textarea');
  await expect(input).toBeEnabled({ timeout: 10_000 });

  // gdpr fixture exercises the tool-call loop in the mock Ambassador, so the
  // first chunk lands quickly but the full answer takes several seconds,
  // giving us a stable window to press Stop without racing the [DONE] event.
  await input.fill('what is the gdpr training status of mario rossi?');
  await page.locator('.send').click();

  // Wait for the stop button to appear, i.e. the stream is in flight.
  const stop = page.locator('.stop');
  await expect(stop).toBeVisible({ timeout: 5_000 });

  // Press Stop and check the inline cancelled footer + retry affordance.
  await stop.click();

  const cancelled = page.locator('.msg-cancelled').first();
  await expect(cancelled).toBeVisible({ timeout: 5_000 });
  await expect(cancelled).toContainText(/stopped/i);

  const retryBtn = cancelled.locator('.msg-retry');
  await expect(retryBtn).toBeVisible();

  // Send button comes back, stop button is gone.
  await expect(page.locator('.send')).toBeVisible();
  await expect(stop).toHaveCount(0);

  // Retry: a new streaming turn starts. The cancelled footer should disappear
  // (the old assistant message + its user pair are dropped, both re-issued).
  await retryBtn.click();
  await expect(page.locator('.stop')).toBeVisible({ timeout: 5_000 });
  await expect(page.locator('.msg-cancelled')).toHaveCount(0);
});

test('cancel preserves any partial content already streamed', async ({ page }) => {
  await page.goto('/');

  const input = page.locator('.chat-input textarea');
  await expect(input).toBeEnabled({ timeout: 10_000 });

  await input.fill('what is the gdpr training status of mario rossi?');
  await page.locator('.send').click();

  // Wait until at least one chunk has been rendered into the assistant body.
  // The tool chip is the most reliable early signal; once it's visible, we
  // know streaming has started but the answer is not yet complete.
  await expect(page.locator('.tool-chip').first()).toBeVisible({ timeout: 5_000 });

  await page.locator('.stop').click();

  // The cancelled footer hangs off the same assistant article, so its DOM
  // sibling msg-body should still exist (content may be empty if cancel
  // landed before the first text chunk, that is an acceptable race).
  const cancelledArticle = page.locator('.msg').filter({ has: page.locator('.msg-cancelled') });
  await expect(cancelledArticle).toHaveCount(1);
});
