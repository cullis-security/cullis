import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from 'react';

interface Props {
  onSend: (text: string) => void;
  disabled?: boolean;
  isSending?: boolean;
  /** When set, replaces the textarea content (used by hint buttons). */
  draft?: string;
  onDraftConsumed?: () => void;
}

export function MessageInput({ onSend, disabled, isSending, draft, onDraftConsumed }: Props) {
  const [value, setValue] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  // Hint click → fill the textarea, focus it, leave the user one keystroke
  // away from sending.
  useEffect(() => {
    if (draft !== undefined && draft.length > 0) {
      setValue(draft);
      textareaRef.current?.focus();
      onDraftConsumed?.();
    }
  }, [draft, onDraftConsumed]);

  // Auto-grow textarea with content, capped by chat-input max-height.
  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 320)}px`;
  }, [value]);

  function submit(e?: FormEvent) {
    e?.preventDefault();
    const text = value.trim();
    if (!text || disabled || isSending) return;
    onSend(text);
    setValue('');
  }

  function onKey(e: KeyboardEvent<HTMLTextAreaElement>) {
    // Enter sends. Shift+Enter inserts a newline.
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      submit();
    }
  }

  const submitDisabled = disabled || isSending || value.trim().length === 0;

  return (
    <form className={`chat-input ${isSending ? 'is-sending' : ''}`} onSubmit={submit}>
      <span className="prompt" aria-hidden="true">▸</span>
      <textarea
        ref={textareaRef}
        rows={1}
        placeholder={isSending ? 'Awaiting answer ...' : 'Compose a message ...'}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={onKey}
        disabled={disabled}
        aria-label="Message"
      />
      <button type="submit" className="send" disabled={submitDisabled}>
        <span className="send-label">{isSending ? 'sending' : 'send'}</span>
        <span className="send-arrow" aria-hidden="true">→</span>
      </button>
    </form>
  );
}
