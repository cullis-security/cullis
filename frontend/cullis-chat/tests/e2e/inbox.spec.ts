import { expect, test } from '@playwright/test';

/**
 * Inbox surface end-to-end.
 *
 * Talks to the mock Ambassador at :7777 (mock/ambassador.mjs) which
 * seeds one row from the night-reporter agent. The dev server boots
 * the SPA so /inbox is a real Astro static page that mounts the
 * <Inbox /> React island.
 */

test('inbox: seeded message renders with principal badge + verify chip', async ({ page }) => {
  await page.goto('/inbox');

  // Page header
  await expect(page.locator('.inbox-title')).toContainText(/Messages/i);

  // Sidebar surface link is marked active for /inbox
  await expect(page.locator('.sl-surface-active')).toContainText(/Inbox/i);

  // The seed row from the mock is visible: agent sender, subject, badge
  const row = page.locator('.inbox-row').first();
  await expect(row).toBeVisible({ timeout: 10_000 });
  await expect(row.locator('.principal-badge-agent')).toContainText(/Agent/i);
  await expect(row).toContainText('night-reporter');
  await expect(row).toContainText(/Cross-company-flagged/i);
  await expect(row.locator('.verify-chip-ok')).toContainText(/verified/i);
});

test('inbox: open detail panel and ack flips chip', async ({ page }) => {
  await page.goto('/inbox');
  await page.locator('.inbox-row').first().click();

  // Detail panel populates
  await expect(page.locator('.msg-detail-subject')).toContainText(/Cross-company/i);
  await expect(page.locator('.msg-detail-pre')).toContainText('CLM-2026-0412');

  // Audit chain placeholder is honest about the missing endpoint
  await expect(page.locator('.msg-detail-audit-pending')).toContainText(
    /audit chain detail/i,
  );

  // Mark read flips the verification chip from pending to delivered
  await page.getByRole('button', { name: 'Mark read' }).click();
  // The "Mark read" button hides once the row is no longer pending
  await expect(page.getByRole('button', { name: 'Mark read' })).toHaveCount(0, {
    timeout: 5_000,
  });
});

test('inbox: compose form submits and toast confirms', async ({ page }) => {
  await page.goto('/inbox');
  await page.getByRole('button', { name: '+ Compose' }).click();

  // Compose form is visible
  await expect(page.locator('.msg-compose')).toBeVisible();

  // Send button disabled until required fields filled
  const sendBtn = page.getByRole('button', { name: 'Send' });
  await expect(sendBtn).toBeDisabled();

  await page.getByLabel('recipient org').fill('asia-pacific');
  await page.getByLabel('recipient name').fill('counterparty-liaison');
  await page.getByLabel('body').fill('Cross-company verification request.');

  // Once required fields are filled the button enables and submits
  await expect(sendBtn).toBeEnabled();
  await sendBtn.click();

  // Success toast appears
  await expect(page.locator('.inbox-toast-success')).toContainText(/sent/i, {
    timeout: 5_000,
  });
});

test('inbox: empty unread tab once seed is acked', async ({ page }) => {
  await page.goto('/inbox');

  // Seed is initially unread; ack via detail panel.
  await page.locator('.inbox-row').first().click();
  await page.getByRole('button', { name: 'Mark read' }).click();
  await expect(page.getByRole('button', { name: 'Mark read' })).toHaveCount(0);

  // Switch to Unread tab — empty state should render
  await page.getByRole('button', { name: 'Unread' }).click();
  await expect(page.locator('.inbox-empty-title')).toContainText(/caught up/i);
});
