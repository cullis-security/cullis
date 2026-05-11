import { useState, type MouseEvent } from 'react';
import { copyToClipboard } from '../lib/clipboard';

interface Props {
  /** The literal text written to the clipboard. */
  text: string;
  /** Hint surfaced via aria-label, e.g. "message", "code". */
  label?: string;
  /** Override the root class. Default `copy-btn` keeps it visually
   *  consistent with the message-level overlay. Code blocks pass a
   *  more specific class. */
  className?: string;
}

/**
 * Square overlay that writes `text` to the clipboard on click.
 *
 * Transient 'copied' state for 1.2s gives visual confirmation. The
 * button stops the parent click event so it does not also toggle the
 * assistant-message audit cross-highlight when placed inside `.msg`.
 */
export function CopyButton({ text, label, className = 'copy-btn' }: Props) {
  const [copied, setCopied] = useState(false);

  async function handleClick(e: MouseEvent<HTMLButtonElement>) {
    e.stopPropagation();
    const ok = await copyToClipboard(text);
    if (!ok) return;
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  }

  const aria = copied ? 'Copied to clipboard' : label ? `Copy ${label}` : 'Copy';
  return (
    <button
      type="button"
      className={`${className}${copied ? ' is-copied' : ''}`}
      onClick={handleClick}
      aria-label={aria}
    >
      <span className="copy-btn-label" aria-hidden="true">
        {copied ? 'copied' : 'copy'}
      </span>
    </button>
  );
}
