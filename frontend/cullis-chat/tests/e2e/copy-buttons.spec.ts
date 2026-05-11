import { expect, test } from '@playwright/test';

test('copy button on assistant message turns to "copied" then resets', async ({ page, context }) => {
  // The clipboard API needs an explicit permission grant in Chromium.
  // We also test the visible state transition (label + class) so the spec
  // does not depend on actually reading the clipboard, which would require
  // a separate browser-side permissions dance in some Playwright versions.
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/');

  const input = page.locator('.chat-input textarea');
  await expect(input).toBeEnabled({ timeout: 10_000 });

  await input.fill('ciao');
  await page.locator('.send').click();

  // Wait for the assistant message body to be rendered.
  const assistantMsg = page.locator('.msg-assistant').last();
  await expect(assistantMsg).toBeVisible({ timeout: 15_000 });
  await expect(assistantMsg.locator('.msg-body-assistant')).toContainText(/cullis|mcp|gdpr/i, {
    timeout: 15_000,
  });

  // Click copy. Force is needed because the button is opacity:0 until
  // hover; Playwright would otherwise complain about non-interactable.
  const copyBtn = assistantMsg.locator('.copy-btn');
  await expect(copyBtn).toHaveCount(1);
  await copyBtn.click({ force: true });

  await expect(copyBtn).toHaveClass(/is-copied/);
  await expect(copyBtn.locator('.copy-btn-label')).toHaveText(/copied/i);

  // The 'copied' state reverts after 1.2s.
  await expect(copyBtn).not.toHaveClass(/is-copied/, { timeout: 2_000 });
  await expect(copyBtn.locator('.copy-btn-label')).toHaveText(/copy/i);
});

test('copy button on user message is wired and shows the same transient state', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/');

  const input = page.locator('.chat-input textarea');
  await expect(input).toBeEnabled({ timeout: 10_000 });
  await input.fill('hello');
  await page.locator('.send').click();

  const userMsg = page.locator('.msg-user').last();
  await expect(userMsg).toBeVisible({ timeout: 5_000 });

  const copyBtn = userMsg.locator('.copy-btn');
  await expect(copyBtn).toHaveCount(1);
  await copyBtn.click({ force: true });
  await expect(copyBtn).toHaveClass(/is-copied/);
});

test('code blocks get their own copy overlay after Shiki highlights', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/');

  const input = page.locator('.chat-input textarea');
  await expect(input).toBeEnabled({ timeout: 10_000 });

  // gdpr fixture in the mock Ambassador returns markdown with a SQL fence.
  await input.fill('what is the gdpr training status of mario rossi?');
  await page.locator('.send').click();

  // The gdpr fixture streams chunks. While `pending` is true, MarkdownView
  // re-renders the markdown body on every chunk, which means
  // `dangerouslySetInnerHTML` wipes and rebuilds .code-block-wrap each
  // time. A click on the button right now would be followed by the next
  // chunk destroying that button before the `is-copied` class can be
  // read. Wait for the streaming caret to disappear (pending=false) so
  // the DOM is stable before interacting.
  await expect(page.locator('.markdown-body.is-pending')).toHaveCount(0, {
    timeout: 20_000,
  });
  // Sprint 1 Step 6 PR-B fires `appendConversationMessage` +
  // `renameConversation` immediately after pending=false. Both are
  // best-effort fire-and-forget calls but they tie up the same single
  // browser thread Shiki is racing against. Wait for the network to
  // quiesce so the highlight pass and the React state for the copy
  // button have settled before we click.
  await page.waitForLoadState('networkidle');

  // Wait directly on the .code-copy overlay rather than on the wrap.
  // The wrap is created synchronously when marked parses the code
  // fence; the overlay is appended by the Shiki post-render hook,
  // which is async (lazy import + per-language load). Locating the
  // copy button itself is the only assertion that proves the whole
  // highlight pipeline finished and the persistence-overhead added
  // by Step 6 PR-B did not delay it past the per-step default.
  const codeCopy = page
    .locator('.msg-assistant .code-block-wrap .code-copy')
    .first();
  await expect(codeCopy).toBeVisible({ timeout: 20_000 });

  await codeCopy.click({ force: true });
  await expect(codeCopy).toHaveClass(/is-copied/);
  await expect(codeCopy.locator('.copy-btn-label')).toHaveText(/copied/i);
  await expect(codeCopy).not.toHaveClass(/is-copied/, { timeout: 2_000 });
});
