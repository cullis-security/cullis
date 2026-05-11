import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import { ChatContext, type ChatContextValue } from '../lib/chat-context';
import { ApiError, chatCompletionStream } from '../lib/api';
import { ensureSession } from '../lib/session-singleton';
import { readSelectedModel } from './ModelPicker';
import type { ChatMessage } from '../lib/types';
import { ChatWindow } from './ChatWindow';
import { AuditPanel } from './AuditPanel';
import '../styles/chat-window.css';

// In production the audit chain belongs to the CISO/admin dashboard,
// not to the end-user chat surface. The inline panel is dev-only and
// gated by an Astro public env var. Default off.
const AUDIT_PANEL_ENABLED = import.meta.env.PUBLIC_DEV_AUDIT_PANEL === '1';

interface ChatState {
  messages: ChatMessage[];
  status: 'idle' | 'sending';
  error: string | null;
  selectedMessageId: string | null;
  draft?: string;
}

type Action =
  | { type: 'append'; message: ChatMessage }
  | { type: 'patch'; id: string; patch: Partial<ChatMessage> }
  | { type: 'append_tool'; id: string; tool: string }
  | { type: 'finish_tool'; id: string; tool: string; latency_ms: number }
  | { type: 'sending' }
  | { type: 'idle' }
  | { type: 'error'; message: string }
  | { type: 'select_message'; id: string | null }
  | { type: 'set_draft'; text: string }
  | { type: 'clear_draft' }
  | { type: 'truncate_at'; index: number };

function reducer(state: ChatState, action: Action): ChatState {
  switch (action.type) {
    case 'append':
      return { ...state, messages: [...state.messages, action.message] };
    case 'patch':
      return {
        ...state,
        messages: state.messages.map((m) =>
          m.id === action.id ? { ...m, ...action.patch } : m,
        ),
      };
    case 'append_tool':
      return {
        ...state,
        messages: state.messages.map((m) => {
          if (m.id !== action.id) return m;
          const calls = m.toolCalls ?? [];
          return {
            ...m,
            toolCalls: [...calls, { name: action.tool, status: 'pending' }],
          };
        }),
      };
    case 'finish_tool':
      return {
        ...state,
        messages: state.messages.map((m) => {
          if (m.id !== action.id) return m;
          const calls = (m.toolCalls ?? []).map((c) =>
            c.name === action.tool && c.status === 'pending'
              ? { name: c.name, status: 'done' as const, latency_ms: action.latency_ms }
              : c,
          );
          return { ...m, toolCalls: calls };
        }),
      };
    case 'sending':
      return { ...state, status: 'sending', error: null };
    case 'idle':
      return { ...state, status: 'idle' };
    case 'error':
      return { ...state, status: 'idle', error: action.message };
    case 'select_message':
      return { ...state, selectedMessageId: action.id };
    case 'set_draft':
      return { ...state, draft: action.text };
    case 'clear_draft':
      return { ...state, draft: undefined };
    case 'truncate_at':
      return { ...state, messages: state.messages.slice(0, Math.max(0, action.index)) };
  }
}

const INITIAL: ChatState = {
  messages: [],
  status: 'idle',
  error: null,
  selectedMessageId: null,
};

const FLUSH_MS = 60;

function newId(prefix: string): string {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`;
}

function isAbortError(err: unknown): boolean {
  // `fetch` rejects an AbortController.abort() with a DOMException whose
  // name is "AbortError"; the ReadableStream reader can also throw the same
  // shape when its parent signal aborts.
  return typeof err === 'object' && err !== null && (err as { name?: unknown }).name === 'AbortError';
}

function reasonOf(err: unknown): string {
  if (err instanceof ApiError) {
    const msg =
      typeof err.payload === 'object' && err.payload && 'message' in err.payload
        ? String((err.payload as { message?: unknown }).message)
        : `HTTP ${err.status}`;
    return msg;
  }
  if (err instanceof Error) return err.message;
  return String(err);
}

/**
 * ChatApp — single React island that owns the shared state for both
 * the chat surface and the audit panel. Wraps both in a context so
 * cross-highlights and audit-row click scroll-to are trivial.
 */
export default function ChatApp() {
  const [state, dispatch] = useReducer(reducer, INITIAL);
  const [sessionReady, setSessionReady] = useState(false);
  // One in-flight stream per chat instance. Stop button aborts via this.
  const abortRef = useRef<AbortController | null>(null);

  // Session init at mount.
  useEffect(() => {
    let cancelled = false;
    ensureSession()
      .then(() => !cancelled && setSessionReady(true))
      .catch((err) => {
        if (cancelled) return;
        dispatch({ type: 'error', message: `session_init: ${reasonOf(err)}` });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Cross-highlight auto-clear after 1.5s.
  useEffect(() => {
    if (!state.selectedMessageId) return;
    const t = window.setTimeout(() => dispatch({ type: 'select_message', id: null }), 1500);
    return () => window.clearTimeout(t);
  }, [state.selectedMessageId]);

  const send = useCallback(async (text: string, historyOverride?: ChatMessage[]) => {
    if (!sessionReady) {
      dispatch({ type: 'error', message: 'Session is not ready yet, try again in a moment.' });
      return;
    }
    // If a previous stream is still in flight, abort it before starting a new one.
    // Prevents two concurrent streams stepping on the same placeholder id space.
    abortRef.current?.abort();

    const userMsg: ChatMessage = {
      id: newId('m'),
      role: 'user',
      content: text,
      createdAt: Date.now(),
    };
    dispatch({ type: 'append', message: userMsg });

    const placeholder: ChatMessage = {
      id: newId('m'),
      role: 'assistant',
      content: '',
      createdAt: Date.now(),
      pending: true,
    };
    dispatch({ type: 'append', message: placeholder });
    dispatch({ type: 'sending' });

    const ctrl = new AbortController();
    abortRef.current = ctrl;

    const accumulator = { content: '' };
    let lastFlush = 0;
    function flush(force = false) {
      const now = Date.now();
      if (!force && now - lastFlush < FLUSH_MS) return;
      lastFlush = now;
      dispatch({ type: 'patch', id: placeholder.id, patch: { content: accumulator.content } });
    }

    try {
      const baseHistory = historyOverride ?? state.messages;
      const history = baseHistory.concat(userMsg).map((m) => ({ role: m.role, content: m.content }));
      const events = chatCompletionStream(
        { model: readSelectedModel(), messages: history },
        ctrl.signal,
      );

      let traceId: string | undefined;
      for await (const ev of events) {
        if (ev.kind === 'chunk') {
          const delta = ev.chunk.choices?.[0]?.delta?.content ?? '';
          if (delta) {
            accumulator.content += delta;
            flush();
          }
          if (!traceId) traceId = ev.chunk.id;
          if (ev.chunk.cullis_audit) {
            dispatch({
              type: 'patch',
              id: placeholder.id,
              patch: { trace_id: ev.chunk.cullis_audit.trace_id, audit: ev.chunk.cullis_audit },
            });
          }
        } else if (ev.kind === 'tool_start') {
          dispatch({ type: 'append_tool', id: placeholder.id, tool: ev.tool });
        } else if (ev.kind === 'tool_end') {
          dispatch({ type: 'finish_tool', id: placeholder.id, tool: ev.tool, latency_ms: ev.latency_ms });
        } else if (ev.kind === 'audit') {
          dispatch({
            type: 'patch',
            id: placeholder.id,
            patch: { trace_id: ev.audit.trace_id, audit: ev.audit },
          });
        } else if (ev.kind === 'done') {
          break;
        }
      }

      flush(true);
      dispatch({ type: 'patch', id: placeholder.id, patch: { pending: false, trace_id: traceId } });
      dispatch({ type: 'idle' });
    } catch (err) {
      flush(true);
      if (isAbortError(err)) {
        // User pressed Stop. Keep partial content, mark cancelled.
        dispatch({ type: 'patch', id: placeholder.id, patch: { pending: false, cancelled: true } });
        dispatch({ type: 'idle' });
        return;
      }
      // Genuine failure: keep partial content if any, surface error inline.
      dispatch({
        type: 'patch',
        id: placeholder.id,
        patch: { pending: false, error: reasonOf(err) },
      });
      dispatch({ type: 'idle' });
    } finally {
      if (abortRef.current === ctrl) abortRef.current = null;
    }
  }, [sessionReady, state.messages]);

  const cancel = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  const retry = useCallback((assistantMessageId: string) => {
    // Find the assistant message we want to re-roll and the user turn that
    // immediately preceded it. Drop both, then re-send the same user text;
    // ChatApp's send() will append a fresh user + placeholder and stream.
    const msgs = state.messages;
    const idx = msgs.findIndex((m) => m.id === assistantMessageId);
    if (idx < 0) return;
    const userIdx = idx - 1;
    if (userIdx < 0 || msgs[userIdx].role !== 'user') return;
    const userText = msgs[userIdx].content;
    const historyBefore = msgs.slice(0, userIdx);
    dispatch({ type: 'truncate_at', index: userIdx });
    void send(userText, historyBefore);
  }, [state.messages, send]);

  const value = useMemo<ChatContextValue>(
    () => ({
      messages: state.messages,
      status: state.status,
      error: state.error,
      selectedMessageId: state.selectedMessageId,
      selectMessage: (id) => dispatch({ type: 'select_message', id }),
      send,
      cancel,
      retry,
      draft: state.draft,
      setDraft: (text) => dispatch({ type: 'set_draft', text }),
      consumeDraft: () => dispatch({ type: 'clear_draft' }),
      sessionReady,
    }),
    [state, send, cancel, retry, sessionReady],
  );

  // Initial collapse state from localStorage. The TopBar toggle script
  // mutates the data-attribute on this element directly; we just seed it.
  // Only relevant when the audit panel is enabled.
  const collapsed = AUDIT_PANEL_ENABLED ? readCollapsedFromLocalStorage() : false;

  const className = AUDIT_PANEL_ENABLED ? 'chat-app' : 'chat-app chat-app--no-audit';

  return (
    <ChatContext.Provider value={value}>
      <div className={className} data-audit-collapsed={collapsed ? 'true' : 'false'}>
        <section className="chat-main" aria-label="Chat">
          <ChatWindow />
        </section>
        {AUDIT_PANEL_ENABLED ? <AuditPanel /> : null}
      </div>
    </ChatContext.Provider>
  );
}

function readCollapsedFromLocalStorage(): boolean {
  try {
    return window.localStorage.getItem('cullis-chat:audit-collapsed') === 'true';
  } catch {
    return false;
  }
}
