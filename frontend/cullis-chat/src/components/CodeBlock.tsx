import { useEffect, useState } from 'react';
import { ensureLanguage, getHighlighter, SHIKI_THEME } from '../lib/shiki';
import { CopyButton } from './CopyButton';

interface Props {
  /** Language tag from the fence, e.g. `language-sql` → `sql`. */
  language: string;
  /** Code text, already sanitised (escaped) by the markdown pipeline. */
  code: string;
}

/**
 * Fenced code block, rendered with Shiki and a React `<CopyButton>`
 * overlay. Drop-in replacement for the previous `<pre>` + vanilla DOM
 * post-processing in `lib/markdown.ts`.
 *
 * Why this exists in M3: during streaming, `MarkdownView`'s `text`
 * prop changes on every SSE delta. The old pipeline rebuilt the DOM
 * via `dangerouslySetInnerHTML`, which wiped the `.code-block-wrap` +
 * `.code-copy` nodes the post-render hook had attached, leaving any
 * `is-copied` timer orphaned. Moving the wrap and the copy button
 * inside the React tree means React reconciles them across renders
 * and the `is-copied` state survives a re-highlight.
 */
export function CodeBlock({ language, code }: Props) {
  const [html, setHtml] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const hi = await getHighlighter();
        const finalLang = await ensureLanguage(hi, language);
        const out = hi.codeToHtml(code, { lang: finalLang, theme: SHIKI_THEME });
        if (!cancelled) setHtml(out);
      } catch (err) {
        // Highlight failure is cosmetic — keep the plain pre/code fallback.
        // eslint-disable-next-line no-console
        console.warn('shiki highlight failed:', err);
        if (!cancelled) setHtml(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [language, code]);

  return (
    <div className="code-block-wrap">
      <CopyButton text={code} label="code" className="code-copy" />
      {html !== null ? (
        // Shiki output is HTML it produced itself; the code text it
        // wraps was already sanitised as part of the markdown pass.
        // No further sanitisation needed here.
        <div className="shiki-block" dangerouslySetInnerHTML={{ __html: html }} />
      ) : (
        <pre className="shiki-fallback">
          <code className={`language-${language}`}>{code}</code>
        </pre>
      )}
    </div>
  );
}
