import { expect, test } from '@playwright/test';

/**
 * Sprint 1 Step 6 PR-C, end-to-end coverage of the sidebar conversation
 * history flow.
 *
 * The mock Ambassador (mock/ambassador.mjs) keeps a per-process in-memory
 * map of conversations + messages so every spec can assume it starts
 * from an empty list. Tests run sequentially via `test.describe.serial`
 * to keep that assumption simple.
 */

test.describe.serial('conversation history sidebar', () => {
  test('first send auto-creates a conversation + shows up in sidebar', async ({ page }) => {
    await page.goto('/');

    const input = page.locator('.chat-input textarea');
    await expect(input).toBeEnabled({ timeout: 10_000 });

    await input.fill('first conversation');
    await page.locator('.send').click();

    await expect(page.locator('.msg-assistant').last()).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('.markdown-body.is-pending')).toHaveCount(0, { timeout: 15_000 });

    // Sidebar lists exactly one conversation with the truncated title.
    const items = page.locator('.conv-item');
    await expect(items).toHaveCount(1, { timeout: 5_000 });
    await expect(items.first().locator('.conv-item-title')).toContainText('first conversation');
  });

  test('reload re-hydrates the active conversation from sessionStorage', async ({ page }) => {
    await page.goto('/');

    const input = page.locator('.chat-input textarea');
    await expect(input).toBeEnabled({ timeout: 10_000 });
    await input.fill('persistence check');
    await page.locator('.send').click();
    await expect(page.locator('.markdown-body.is-pending')).toHaveCount(0, { timeout: 15_000 });

    // Hard reload: sessionStorage survives, the conv id is read back
    // at mount, and the messages re-render.
    await page.reload();

    // The user message + the assistant reply both come back.
    await expect(page.locator('.msg-user').last()).toContainText('persistence check', {
      timeout: 5_000,
    });
    await expect(page.locator('.msg-assistant').last()).toBeVisible({ timeout: 5_000 });
  });

  test('clicking a sidebar row loads its history', async ({ page }) => {
    await page.goto('/');
    const input = page.locator('.chat-input textarea');
    await expect(input).toBeEnabled({ timeout: 10_000 });

    // Conversation A.
    await input.fill('alpha message');
    await page.locator('.send').click();
    await expect(page.locator('.markdown-body.is-pending')).toHaveCount(0, { timeout: 15_000 });

    // Clear sessionStorage + reload to fall back into a fresh thread.
    await page.evaluate(() => window.sessionStorage.removeItem('cullis-chat:conv-id'));
    await page.reload();

    // Conversation B.
    await page.locator('.chat-input textarea').fill('bravo message');
    await page.locator('.send').click();
    await expect(page.locator('.markdown-body.is-pending')).toHaveCount(0, { timeout: 15_000 });

    // Two rows in the sidebar; click the older one and verify alpha
    // text reappears in the main column.
    const items = page.locator('.conv-item');
    await expect(items).toHaveCount(2, { timeout: 5_000 });

    // The most recent (bravo) sits at the top; the older (alpha) is
    // the last item.
    await items.last().locator('.conv-item-title').click();
    await expect(page.locator('.msg-user').last()).toContainText('alpha message', {
      timeout: 5_000,
    });
  });

  test('delete removes the row from the sidebar', async ({ page }) => {
    await page.goto('/');
    page.on('dialog', (d) => void d.accept());

    const input = page.locator('.chat-input textarea');
    await expect(input).toBeEnabled({ timeout: 10_000 });
    await input.fill('to be deleted');
    await page.locator('.send').click();
    await expect(page.locator('.markdown-body.is-pending')).toHaveCount(0, { timeout: 15_000 });

    const items = page.locator('.conv-item');
    const before = await items.count();
    expect(before).toBeGreaterThan(0);

    // Delete the active row. The button is opacity:0 until hover so
    // we force the click to bypass interactability.
    const active = page.locator('.conv-item.conv-item-active');
    await expect(active).toHaveCount(1);
    await active.locator('.conv-item-delete').click({ force: true });

    await expect(items).toHaveCount(before - 1, { timeout: 5_000 });
  });

  test('new chat link clears the active conversation', async ({ page }) => {
    await page.goto('/');

    const input = page.locator('.chat-input textarea');
    await expect(input).toBeEnabled({ timeout: 10_000 });
    await input.fill('seed for new chat test');
    await page.locator('.send').click();
    await expect(page.locator('.markdown-body.is-pending')).toHaveCount(0, { timeout: 15_000 });

    // Click the New chat link in the sidebar.
    await page.locator('.sl-new-chat').click();

    // After the reload we should be back at the empty state (no
    // assistant message yet) and sessionStorage should be cleared.
    await expect(page.locator('.chat-empty-title')).toBeVisible({ timeout: 5_000 });
    const stored = await page.evaluate(() => window.sessionStorage.getItem('cullis-chat:conv-id'));
    expect(stored).toBeNull();
  });
});
