import { createContext, useContext } from 'react';
import type { ChatMessage } from './types';

/**
 * Context plumbing for ChatApp. ChatWindow and AuditPanel both
 * consume it; the producer is `ChatApp.tsx`.
 *
 * Keeping this as a tiny module (no JSX) so importing it from a
 * non-React .tsx file or from a Vite worker stays free.
 */

export interface ChatContextValue {
  messages: ChatMessage[];
  status: 'idle' | 'sending';
  error: string | null;
  /** ID of the message the user clicked on (chat ↔ audit cross-highlight). */
  selectedMessageId: string | null;
  selectMessage: (id: string | null) => void;
  send: (text: string) => void;
  /** Bumps a draft into the input box (hint clicks). */
  draft?: string;
  consumeDraft: () => void;
  setDraft: (text: string) => void;
  sessionReady: boolean;
}

export const ChatContext = createContext<ChatContextValue | null>(null);

export function useChat(): ChatContextValue {
  const ctx = useContext(ChatContext);
  if (!ctx) throw new Error('useChat must be used inside <ChatApp>');
  return ctx;
}
