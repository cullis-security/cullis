import type { ChatMessage } from '../lib/types';

interface Props {
  message: ChatMessage;
}

/**
 * One chat turn — user or assistant.
 *
 * v0.1: plain text, `white-space: pre-wrap`. Markdown sanitised
 * rendering arrives in commit 6 (DOMPurify + marked + Shiki).
 */
export function Message({ message }: Props) {
  const isUser = message.role === 'user';
  const ts = new Date(message.createdAt);
  const tsLabel = ts.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  return (
    <article className={`msg msg-${message.role}`} aria-label={`${message.role} message`}>
      <header className="msg-meta">
        <span className={`msg-role ${isUser ? 'msg-role-user' : ''}`}>
          {isUser ? 'mario' : 'cullis'}
        </span>
        <span className="msg-folio">
          <em>{tsLabel}</em>
          {message.trace_id ? <> · {message.trace_id}</> : null}
        </span>
      </header>
      <div className={`msg-body ${message.pending ? 'msg-pending' : ''}`}>{message.content}</div>
    </article>
  );
}
