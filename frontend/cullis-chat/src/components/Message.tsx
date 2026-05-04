import { MarkdownView } from './MarkdownView';
import { ToolCallIndicator } from './ToolCallIndicator';
import type { ChatMessage } from '../lib/types';

interface Props {
  message: ChatMessage;
  selected?: boolean;
  onClick?: () => void;
}

/**
 * One chat turn — user or assistant.
 *
 * Assistant content is rendered through `MarkdownView` (DOMPurify +
 * marked + lazy Shiki). User content is plain text — escaped by React.
 *
 * Tool calls observed during the turn are rendered as inline
 * marginalia chips above the body.
 */
export function Message({ message, selected, onClick }: Props) {
  const isUser = message.role === 'user';
  const ts = new Date(message.createdAt);
  const tsLabel = ts.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  const tools = message.toolCalls ?? [];

  return (
    <article
      className={`msg msg-${message.role}${selected ? ' msg-selected' : ''}`}
      aria-label={`${message.role} message`}
      data-message-id={message.id}
      onClick={!isUser && onClick ? onClick : undefined}
      role={!isUser && onClick ? 'button' : undefined}
      tabIndex={!isUser && onClick ? 0 : undefined}
    >
      <header className="msg-meta">
        <span className={`msg-role ${isUser ? 'msg-role-user' : ''}`}>
          {isUser ? 'mario' : 'cullis'}
        </span>
        <span className="msg-folio">
          <em>{tsLabel}</em>
          {message.trace_id ? <> · {message.trace_id}</> : null}
        </span>
      </header>

      {tools.length > 0 ? (
        <div className="msg-tools" aria-label="Tools used in this turn">
          {tools.map((t, i) => (
            <ToolCallIndicator key={`${t.name}-${i}`} call={t} />
          ))}
        </div>
      ) : null}

      {isUser ? (
        <div className="msg-body msg-body-user">{message.content}</div>
      ) : (
        <div className={`msg-body msg-body-assistant${message.pending ? ' msg-pending' : ''}`}>
          {message.content.length > 0 ? (
            <MarkdownView text={message.content} pending={message.pending} />
          ) : (
            <span className="msg-empty-pending" aria-label="awaiting first chunk">
              <em>thinking</em>
            </span>
          )}
        </div>
      )}
    </article>
  );
}
