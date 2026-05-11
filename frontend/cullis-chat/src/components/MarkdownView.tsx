import { Children, isValidElement, type ReactNode } from 'react';
import ReactMarkdown from 'react-markdown';
import rehypeSanitize, { defaultSchema } from 'rehype-sanitize';
import remarkGfm from 'remark-gfm';
import { CodeBlock } from './CodeBlock';

interface Props {
  text: string;
  /** Adds the streaming caret `▍` after the last block. */
  pending?: boolean;
}

/**
 * Sanitisation schema for assistant markdown (ADR-019 §6).
 *
 *   - No `<img>`, `<svg>`, `<iframe>`, `<script>`, `<form>`, `<button>`, `<input>`.
 *   - Anchors restricted to `http|https|mailto`.
 *   - `style` attribute denied (Shiki inline styles enter the DOM via
 *     `<CodeBlock>` after sanitisation, not through this path).
 *   - GFM tables, strikethrough, autolinks via `remark-gfm`.
 */
const SCHEMA = {
  ...defaultSchema,
  tagNames: [
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
  ],
  attributes: {
    ...defaultSchema.attributes,
    '*': ['className'],
    a: ['href', 'target', 'rel'],
    code: ['className'],
    span: ['className'],
  },
  protocols: {
    ...defaultSchema.protocols,
    href: ['http', 'https', 'mailto'],
  },
};

/** Force every anchor through `target=_blank` + `rel=noopener noreferrer`. */
function SafeAnchor({ href, children }: { href?: string; children?: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  );
}

/**
 * Intercept the `<pre>` wrapper react-markdown emits around fenced
 * code blocks and replace it with `<CodeBlock>`. The single child is
 * a `<code class="language-X">…</code>`; we read its className and
 * text content via React.Children.
 */
function PreBlock({ children }: { children?: ReactNode }) {
  const codeChild = Children.toArray(children).find(isValidElement);
  if (!codeChild) {
    return <pre>{children}</pre>;
  }
  const props = (codeChild as { props?: { className?: string; children?: ReactNode } }).props ?? {};
  const match = /language-(\w+)/.exec(props.className ?? '');
  const language = match ? match[1] : 'text';
  const raw = props.children;
  const code = typeof raw === 'string'
    ? raw
    : Array.isArray(raw)
      ? raw.join('')
      : raw == null
        ? ''
        : String(raw);
  return <CodeBlock language={language} code={code.replace(/\n$/, '')} />;
}

/**
 * Render sanitised markdown through react-markdown.
 *
 * Unlike the previous pipeline (marked + DOMPurify + manual DOM
 * surgery in a useEffect), the React tree is the only owner of the
 * rendered output. Streaming deltas re-run the markdown parser, but
 * `<CodeBlock>` keeps its highlight + copy state across re-renders
 * because it lives inside the React reconciliation graph.
 */
export function MarkdownView({ text, pending }: Props) {
  return (
    <div className={`markdown-body${pending ? ' is-pending' : ''}`}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[[rehypeSanitize, SCHEMA]]}
        components={{
          a: SafeAnchor,
          pre: PreBlock,
        }}
      >
        {text}
      </ReactMarkdown>
    </div>
  );
}
