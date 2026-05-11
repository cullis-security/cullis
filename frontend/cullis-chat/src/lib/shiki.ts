/**
 * Lazy Shiki highlighter — single shared instance, loaded the first
 * time a fenced code block enters the React tree. Bundle (~600 kB)
 * stays in its own client chunk thanks to dynamic import.
 *
 * Used by `<CodeBlock>` to produce the inner `<pre class="shiki">…</pre>`
 * HTML. Shiki escapes the code text it receives, so its output is
 * safe to drop into the DOM via `dangerouslySetInnerHTML` even though
 * it carries inline `style` attributes that rehype-sanitize would
 * otherwise strip — the substitution happens *after* sanitisation,
 * on text whose body was already sanitised as part of the markdown
 * pass.
 */

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
export const SHIKI_THEME = 'github-dark-default';

interface MinimalHighlighter {
  codeToHtml(code: string, opts: { lang: string; theme: string }): string;
  getLoadedLanguages(): string[];
  loadLanguage(lang: string): Promise<unknown>;
}

let highlighterPromise: Promise<MinimalHighlighter> | null = null;

export async function getHighlighter(): Promise<MinimalHighlighter> {
  if (!highlighterPromise) {
    highlighterPromise = import('shiki').then(({ createHighlighter }) =>
      createHighlighter({
        themes: [SHIKI_THEME],
        langs: SHIKI_LANGS,
      }) as Promise<MinimalHighlighter>,
    );
  }
  return highlighterPromise;
}

export async function ensureLanguage(hi: MinimalHighlighter, lang: string): Promise<string> {
  if (hi.getLoadedLanguages().includes(lang)) return lang;
  try {
    await hi.loadLanguage(lang);
    return lang;
  } catch {
    return 'text';
  }
}
