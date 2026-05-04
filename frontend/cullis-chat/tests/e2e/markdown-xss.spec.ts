import { expect, test } from '@playwright/test';

test('markdown XSS: dangerous tags in assistant content are neutralised', async ({ page }) => {
  // Fail loudly if a JS-driven dialog ever opens (alert / confirm / prompt).
  let dialogFired = false;
  page.on('dialog', async (d) => {
    dialogFired = true;
    await d.dismiss();
  });

  await page.goto('/');

  const input = page.locator('.chat-input textarea');
  await expect(input).toBeEnabled({ timeout: 10_000 });

  await input.fill('__xss__ test');
  await page.locator('.send').click();

  // Wait for assistant body to render — the heading should render as <h1>.
  await expect(page.locator('.markdown-body h1')).toContainText('XSS test heading', {
    timeout: 15_000,
  });

  // No <script>, no <iframe>, no <img>, no on* handlers, no javascript: URLs.
  const body = page.locator('.markdown-body').last();
  await expect(body.locator('script')).toHaveCount(0);
  await expect(body.locator('iframe')).toHaveCount(0);
  await expect(body.locator('img')).toHaveCount(0);

  // Inline event handlers must be stripped.
  const onClickCount = await body.locator('[onclick]').count();
  expect(onClickCount).toBe(0);
  const onErrorCount = await body.locator('[onerror]').count();
  expect(onErrorCount).toBe(0);

  // Any <a> href that begins with `javascript:` would be a regression.
  const jsLinks = await body.locator('a').evaluateAll((nodes) =>
    nodes.filter((n) => /^javascript:/i.test((n as HTMLAnchorElement).href)).length,
  );
  expect(jsLinks).toBe(0);

  // Window-side flags set by the mock payload's <script>/<img onerror> must be falsy.
  const flags = await page.evaluate(() => ({
    script: (window as unknown as { __cullis_xss?: boolean }).__cullis_xss === true,
    img: (window as unknown as { __cullis_xss_img?: boolean }).__cullis_xss_img === true,
  }));
  expect(flags.script).toBe(false);
  expect(flags.img).toBe(false);

  // No alert / confirm / prompt fired.
  expect(dialogFired).toBe(false);
});
