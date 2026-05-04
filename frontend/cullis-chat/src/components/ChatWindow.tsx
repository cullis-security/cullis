import { useChat } from '../lib/chat-context';
import { MessageList } from './MessageList';
import { MessageInput } from './MessageInput';

/**
 * ChatWindow — the centre pane. State is now owned by `ChatApp` and
 * shared via context, so AuditPanel can mirror selection / scroll-to.
 */
export function ChatWindow() {
  const { messages, status, error, send, draft, setDraft, consumeDraft, sessionReady } = useChat();

  return (
    <div className="chat-shell">
      {error ? (
        <div className="chat-error" role="alert">
          <strong>error</strong>
          {error}
        </div>
      ) : null}

      <MessageList
        messages={messages}
        isEmpty={messages.length === 0}
        onHintClick={(t) => setDraft(t)}
      />

      <MessageInput
        onSend={send}
        disabled={!sessionReady}
        isSending={status === 'sending'}
        draft={draft}
        onDraftConsumed={() => consumeDraft()}
      />

      <p className="chat-foot">
        Bearer · cookie HttpOnly · CSP nonce-locked · markdown sanitised via DOMPurify
      </p>
    </div>
  );
}
