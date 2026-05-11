/**
 * Sprint 1 Step 6 PR-B, dynamic sidebar history.
 *
 * Reads /v1/conversations on mount and renders the principal-scoped
 * list returned by the Connector. Clicking a row dispatches a
 * `cullis:load-conversation` window event that ChatApp's listener
 * picks up to fetch the messages and rehydrate the chat surface.
 * Deletes call DELETE /v1/conversations/{id} and refresh the list.
 *
 * Coordination with ChatApp happens entirely through three custom
 * window events so this component stays a sibling React island
 * inside the Astro static layout instead of being smuggled into
 * the ChatApp tree.
 *
 *   cullis:conversation-created   { id, title }  emitted by ChatApp
 *                                                after the first POST
 *                                                /v1/conversations of
 *                                                a fresh chat.
 *   cullis:conversation-active    { id }         emitted by ChatApp
 *                                                whenever it
 *                                                switches active id
 *                                                (load / new).
 *   cullis:conversation-cleared   no detail      emitted by ChatApp
 *                                                after the user
 *                                                deletes the active
 *                                                conversation.
 */
import { useEffect, useState } from 'react';
import { deleteConversation, listConversations } from '../lib/api';
import type { ConversationSummary } from '../lib/types';

const ACTIVE_ID_KEY = 'cullis-chat:conv-id';

function readActiveId(): string | null {
  try {
    return window.sessionStorage.getItem(ACTIVE_ID_KEY);
  } catch {
    return null;
  }
}

function clearActiveId() {
  try {
    window.sessionStorage.removeItem(ACTIVE_ID_KEY);
  } catch {
    /* ignore */
  }
}

export function ConversationsList() {
  const [items, setItems] = useState<ConversationSummary[]>([]);
  const [activeId, setActiveId] = useState<string | null>(() => readActiveId());
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  async function refresh() {
    try {
      const list = await listConversations({ limit: 20 });
      setItems(list);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoaded(true);
    }
  }

  useEffect(() => {
    void refresh();
    const onCreated = () => void refresh();
    const onCleared = () => {
      setActiveId(null);
      void refresh();
    };
    const onActive = (e: Event) => {
      const detail = (e as CustomEvent).detail || {};
      setActiveId(typeof detail.id === 'string' ? detail.id : null);
      // Refresh so a freshly-titled conv climbs to the top of the list.
      void refresh();
    };
    window.addEventListener('cullis:conversation-created', onCreated);
    window.addEventListener('cullis:conversation-cleared', onCleared);
    window.addEventListener('cullis:conversation-active', onActive);
    return () => {
      window.removeEventListener('cullis:conversation-created', onCreated);
      window.removeEventListener('cullis:conversation-cleared', onCleared);
      window.removeEventListener('cullis:conversation-active', onActive);
    };
  }, []);

  function handleOpen(id: string) {
    setActiveId(id);
    window.dispatchEvent(
      new CustomEvent('cullis:load-conversation', { detail: { id } }),
    );
  }

  async function handleDelete(id: string, evt: React.MouseEvent) {
    evt.stopPropagation();
    if (!window.confirm('Delete this conversation?')) return;
    try {
      await deleteConversation(id);
      if (activeId === id) {
        setActiveId(null);
        clearActiveId();
        window.dispatchEvent(new CustomEvent('cullis:conversation-cleared'));
      }
      void refresh();
    } catch (err) {
      // Surface but do not crash the sidebar.
      // eslint-disable-next-line no-console
      console.warn('delete conversation failed:', err);
    }
  }

  if (error) {
    return (
      <div className="conv-list-error" role="alert">
        <p className="conv-list-error-body">history unavailable</p>
        <p className="conv-list-error-detail">{error}</p>
      </div>
    );
  }

  if (loaded && items.length === 0) {
    return (
      <div className="conv-list-empty">
        <p className="conv-list-empty-body">
          No saved conversations yet. Send a message to start one.
        </p>
      </div>
    );
  }

  return (
    <ul className="conv-list" aria-label="Recent conversations">
      {items.map((c) => (
        <li
          key={c.id}
          className={
            'conv-item' + (c.id === activeId ? ' conv-item-active' : '')
          }
        >
          <button
            type="button"
            className="conv-item-title"
            onClick={() => handleOpen(c.id)}
            title={c.title || 'untitled'}
          >
            {c.title || <em>untitled</em>}
          </button>
          <button
            type="button"
            className="conv-item-delete"
            onClick={(e) => void handleDelete(c.id, e)}
            aria-label={`Delete conversation ${c.title || c.id}`}
          >
            ×
          </button>
        </li>
      ))}
    </ul>
  );
}
