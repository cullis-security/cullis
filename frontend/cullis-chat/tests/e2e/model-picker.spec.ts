import { expect, test } from '@playwright/test';

test('model picker: lists upstream models, persists selection across reload', async ({
  page,
  context,
}) => {
  await page.goto('/');

  const select = page.locator('.model-picker select');
  await expect(select).toBeVisible();

  // Wait for the picker to load the model list (data-loaded='true').
  await expect(page.locator('.model-picker[data-loaded="true"]')).toBeVisible({
    timeout: 10_000,
  });

  // Mock returns 3 routed models: haiku, sonnet, opus.
  const optionTexts = await select.locator('option').allInnerTexts();
  expect(optionTexts).toEqual(
    expect.arrayContaining(['claude-haiku-4-5', 'claude-sonnet-4-6', 'claude-opus-4-7']),
  );

  // Pick a non-default and reload.
  await select.selectOption('claude-opus-4-7');
  await expect(select).toHaveValue('claude-opus-4-7');

  await page.reload();
  await expect(page.locator('.model-picker[data-loaded="true"]')).toBeVisible({
    timeout: 10_000,
  });
  await expect(page.locator('.model-picker select')).toHaveValue('claude-opus-4-7');

  // Cleanup so other specs start from default. Use a pinned origin so
  // `localStorage` resolves to the same partition.
  await context.clearCookies();
  await page.evaluate(() => window.localStorage.removeItem('cullis-chat:model'));
});
