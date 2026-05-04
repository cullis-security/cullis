import { useEffect, useRef } from 'react';
import { Message } from './Message';
import { useChat } from '../lib/chat-context';
import type { ChatMessage } from '../lib/types';

interface Props {
  messages: ChatMessage[];
  onHintClick: (text: string) => void;
  isEmpty: boolean;
}

const HINTS = [
  'what is the gdpr training status of mario rossi?',
  'list active sessions across the org.',
  'summarise the open compliance findings.',
];

export function MessageList({ messages, onHintClick, isEmpty }: Props) {
  const scrollerRef = useRef<HTMLDivElement | null>(null);
  const { selectedMessageId, selectMessage } = useChat();

  // Stick to bottom when new content arrives, unless the user has
  // scrolled away (within 200px of the bottom counts as "at bottom").
  useEffect(() => {
    const el = scrollerRef.current;
    if (!el) return;
    const distance = el.scrollHeight - el.scrollTop - el.clientHeight;
    if (distance < 200) {
      el.scrollTop = el.scrollHeight;
    }
  }, [messages]);

  // Audit row click → scroll-to in chat.
  useEffect(() => {
    if (!selectedMessageId) return;
    const el = scrollerRef.current?.querySelector(
      `[data-message-id="${selectedMessageId}"]`,
    );
    el?.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }, [selectedMessageId]);

  return (
    <div className="chat-stream" ref={scrollerRef} aria-live="polite">
      <div className="chat-stream-inner">
        {isEmpty ? (
          <section className="chat-empty">
            <p className="folio">CLLS-CHAT · <em>session new</em></p>
            <h1 className="chat-empty-title">
              Ask <em>anything</em>.<br />
              Every line is signed.
            </h1>
            <p className="chat-empty-sub">
              Your question is forwarded under your principal identity, audit-chained,
              and the answer arrives with a verifiable trace on the right.
            </p>
            <div className="chat-empty-hints">
              {HINTS.map((h) => (
                <button
                  key={h}
                  type="button"
                  className="hint"
                  onClick={() => onHintClick(h)}
                >
                  ▸ {h}
                </button>
              ))}
            </div>
          </section>
        ) : (
          messages.map((m) => (
            <Message
              key={m.id}
              message={m}
              selected={m.id === selectedMessageId}
              onClick={() => selectMessage(m.id === selectedMessageId ? null : m.id)}
            />
          ))
        )}
      </div>
    </div>
  );
}
