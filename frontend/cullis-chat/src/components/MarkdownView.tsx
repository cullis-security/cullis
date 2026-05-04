import { useEffect, useMemo, useRef } from 'react';
import { highlightCodeBlocks, renderMarkdown } from '../lib/markdown';

interface Props {
  text: string;
  /** Adds the streaming caret `▍` after the last block. */
  pending?: boolean;
}

/**
 * Render sanitised markdown into the DOM.
 *
 * `dangerouslySetInnerHTML` is used here exclusively, and only on the
 * output of the DOMPurify pipeline. Plain text content (user input,
 * placeholder strings, error messages) never goes through this
 * component — we pass it as React children where text is escaped.
 */
export function MarkdownView({ text, pending }: Props) {
  const html = useMemo(() => renderMarkdown(text), [text]);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    void highlightCodeBlocks(el).catch((err: unknown) => {
      // Highlight failure is cosmetic — leave the plain `<pre><code>` block.
      // eslint-disable-next-line no-console
      console.warn('shiki highlight failed:', err);
    });
  }, [html]);

  return (
    <div
      ref={ref}
      className={`markdown-body${pending ? ' is-pending' : ''}`}
      // Sanitised by DOMPurify in renderMarkdown above.
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
