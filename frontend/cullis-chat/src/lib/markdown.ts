/**
 * Markdown pipeline for Cullis Chat (ADR-019 §6).
 *
 *   raw markdown
 *     ↓ marked.parse (sync)        unsafe HTML
 *     ↓ DOMPurify.sanitize         sanitised HTML
 *     ↓ <a> hooks                  forces target=_blank rel=noopener
 *
 * Code blocks are rendered as plain `<pre><code class="language-XYZ">` by
 * marked; the React component (`MarkdownView`) post-processes them with
 * Shiki on the client (lazy-imported).
 *
 * We never call `dangerouslySetInnerHTML` on a string that has not been
 * through this pipeline. Tool args / results / placeholder text use
 * plain React text rendering instead.
 */

import DOMPurify from 'dompurify';
import { marked } from 'marked';

const SAFE_TAGS = [
  'a',
  'p',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'ul',
  'ol',
  'li',
  'strong',
  'em',
  'code',
  'pre',
  'br',
  'hr',
  'table',
  'thead',
  'tbody',
  'tr',
  'th',
  'td',
  'blockquote',
  'span',
  'del',
  'sub',
  'sup',
];

const SAFE_ATTRS = ['href', 'target', 'rel', 'class', 'style', 'data-language'];

let hooksInstalled = false;
function installHooks() {
  if (hooksInstalled) return;
  hooksInstalled = true;
  DOMPurify.addHook('afterSanitizeAttributes', (node) => {
    // Force safe link behaviour. ADR-019 §6 axis 2.
    if (node.tagName === 'A') {
      node.setAttribute('target', '_blank');
      node.setAttribute('rel', 'noopener noreferrer');
    }
    // Strip `style` from anything that isn't a Shiki span (Shiki injects
    // colour styles inline). Easier than allow-listing per-rule.
    if (
      node.hasAttribute &&
      node.hasAttribute('style') &&
      !(node.tagName === 'SPAN' && node.classList?.contains('line'))
    ) {
      node.removeAttribute('style');
    }
  });
}

marked.setOptions({
  gfm: true,
  breaks: false,
});

export function renderMarkdown(text: string): string {
  installHooks();
  const html = marked.parse(text, { async: false }) as string;
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: SAFE_TAGS,
    ALLOWED_ATTR: SAFE_ATTRS,
    ALLOWED_URI_REGEXP: /^(?:https?|mailto):/i,
    FORBID_ATTR: ['onclick', 'onload', 'onmouseover', 'onerror', 'srcdoc', 'srcset'],
    FORBID_TAGS: ['script', 'iframe', 'object', 'embed', 'form', 'input', 'button', 'img', 'svg', 'math'],
  });
}

/**
 * Lazy-loaded Shiki highlighter. Bundle (~600 kB) is split into its own
 * client chunk and only fetched the first time a code block appears.
 */
let highlighterPromise: Promise<unknown> | null = null;
const SHIKI_LANGS = [
  'sql',
  'javascript',
  'typescript',
  'tsx',
  'jsx',
  'python',
  'bash',
  'shell',
  'json',
  'yaml',
  'go',
  'rust',
  'java',
  'html',
  'css',
];
const SHIKI_THEME = 'github-dark-default';

async function getHighlighter() {
  if (!highlighterPromise) {
    highlighterPromise = import('shiki').then(({ createHighlighter }) =>
      createHighlighter({
        themes: [SHIKI_THEME],
        langs: SHIKI_LANGS,
      }),
    );
  }
  return highlighterPromise;
}

/**
 * Highlight every `<pre><code class="language-X">` inside `root`.
 *
 * Idempotent — replaces a `<pre>` with the Shiki output and tags it with
 * `data-shiki="done"` so a second pass on the same node skips it. Useful
 * during streaming, where `MarkdownView` re-runs after each delta.
 */
export async function highlightCodeBlocks(root: HTMLElement): Promise<void> {
  const blocks = root.querySelectorAll<HTMLElement>('pre > code[class*="language-"]:not([data-shiki="done"])');
  if (blocks.length === 0) return;

  // Snapshot — DOM mutates while we run.
  const targets: { lang: string; text: string; pre: HTMLPreElement }[] = [];
  for (const code of Array.from(blocks)) {
    const langClass = Array.from(code.classList).find((c) => c.startsWith('language-'));
    if (!langClass) continue;
    const lang = langClass.replace('language-', '');
    const pre = code.closest('pre');
    if (!pre) continue;
    targets.push({ lang, text: code.textContent ?? '', pre });
  }
  if (targets.length === 0) return;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const hi: any = await getHighlighter();
  for (const { lang, text, pre } of targets) {
    const supported = hi.getLoadedLanguages().includes(lang) || (await safeLoad(hi, lang));
    const finalLang = supported ? lang : 'text';
    const html = hi.codeToHtml(text, { lang: finalLang, theme: SHIKI_THEME });
    // Replace the <pre> with Shiki's <pre>. We mark the new code as done.
    const wrapper = document.createElement('div');
    wrapper.innerHTML = html;
    const newPre = wrapper.firstElementChild as HTMLElement | null;
    if (!newPre) continue;
    const innerCode = newPre.querySelector('code');
    if (innerCode) innerCode.setAttribute('data-shiki', 'done');
    newPre.classList.add('shiki-block');
    pre.replaceWith(newPre);
  }
}

async function safeLoad(hi: { loadLanguage: (l: string) => Promise<unknown> }, lang: string): Promise<boolean> {
  try {
    await hi.loadLanguage(lang);
    return true;
  } catch {
    return false;
  }
}
