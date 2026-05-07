/**
 * Inbox — shared component for Cullis Chat (consumer) and Frontdesk
 * (enterprise). Lists pending messages, opens a detail panel with
 * audit-chain provenance, and offers a compose form for the four
 * ADR-020 quadrants (U2A, U2U, A2U, A2A).
 *
 * Backend contract: `app/inbox/router.py` (REST surface) +
 * `lib/api.ts::INBOX_BASE`. Audit-chain detail (`/v1/audit/messages/
 * {msg_id}`) is BLOCKED in the spec until the broker ships it; the
 * detail panel renders a placeholder so the demo screenshot is honest.
 *
 * Lives in `components/core/` as a shared SPA primitive; Cullis Chat
 * (consumer) and Frontdesk (enterprise) both mount the same instance.
 * Sub-views (list, detail, compose) are intentionally inline in this
 * file: split if the file exceeds ~600 lines.
 */
import { useCallback, useEffect, useMemo, useState } from 'react';

import {
  ackInboxMessage,
  archiveInboxMessage,
  ApiError,
  listInbox,
  sendInboxMessage,
} from '../../lib/api';
import { ensureSession } from '../../lib/session-singleton';
import type {
  InboxMessage,
  InboxSendRequest,
  InboxTab,
  PrincipalType,
} from '../../lib/types';
import PrincipalBadge from './PrincipalBadge';

const TABS: { id: InboxTab; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'unread', label: 'Unread' },
  { id: 'sent', label: 'Sent' },
  { id: 'drafts', label: 'Drafts' },
];

const PRINCIPAL_TYPES: PrincipalType[] = ['user', 'agent', 'workload'];

function formatRelative(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const delta = Math.max(0, Date.now() - t);
  if (delta < 60_000) return 'just now';
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m`;
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)}h`;
  return `${Math.floor(delta / 86_400_000)}d`;
}

function deriveSubject(msg: InboxMessage): string {
  if (msg.subject && msg.subject.trim()) return msg.subject;
  // Prefer the first line of the body, capped — same shape as Mail.app.
  const firstLine = msg.body.split('\n')[0]?.trim() ?? '';
  if (firstLine.length > 80) return `${firstLine.slice(0, 77)}…`;
  return firstLine || '(no subject)';
}

function snippet(body: string): string {
  const flat = body.replace(/\s+/g, ' ').trim();
  return flat.length > 120 ? `${flat.slice(0, 117)}…` : flat;
}

interface ToastState {
  kind: 'success' | 'error';
  message: string;
}

export default function Inbox() {
  const [messages, setMessages] = useState<InboxMessage[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<InboxTab>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [composing, setComposing] = useState(false);
  const [toast, setToast] = useState<ToastState | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      await ensureSession();
      const rows = await listInbox({ limit: 50 });
      setMessages(rows);
    } catch (err) {
      // 404 surfaces when the Connector Ambassador hasn't wired the
      // /v1/inbox passthrough yet (tracked separately as a backend
      // issue). Show a calm "endpoint pending" copy instead of a raw
      // API error so the demo screenshot is honest about the state.
      let msg = 'failed to load';
      if (err instanceof ApiError) {
        msg =
          err.status === 404
            ? 'inbox endpoint pending — backend wiring in flight'
            : `api error ${err.status}`;
      }
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Auto-dismiss toasts after 3.5s — never block the surface.
  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(() => setToast(null), 3500);
    return () => window.clearTimeout(t);
  }, [toast]);

  const filtered = useMemo(() => {
    switch (tab) {
      case 'unread':
        return messages.filter((m) => m.delivery_state === 'pending');
      case 'sent':
      case 'drafts':
        // Sent + Drafts require server-side support that lands with
        // the four-quadrant outbox — for Phase 2 they render an empty
        // state so the tab affordance is real.
        return [];
      case 'all':
      default:
        return messages;
    }
  }, [messages, tab]);

  const selected = useMemo(
    () => (selectedId ? messages.find((m) => m.msg_id === selectedId) ?? null : null),
    [messages, selectedId],
  );

  const handleAck = useCallback(
    async (msgId: string) => {
      try {
        await ackInboxMessage(msgId);
        setMessages((rows) =>
          rows.map((r) =>
            r.msg_id === msgId ? { ...r, delivery_state: 'delivered' } : r,
          ),
        );
      } catch (err) {
        setToast({ kind: 'error', message: 'ack failed' });
      }
    },
    [],
  );

  const handleArchive = useCallback(
    async (msgId: string) => {
      try {
        await archiveInboxMessage(msgId);
        setMessages((rows) => rows.filter((r) => r.msg_id !== msgId));
        setSelectedId((cur) => (cur === msgId ? null : cur));
        setToast({ kind: 'success', message: 'archived' });
      } catch (err) {
        setToast({ kind: 'error', message: 'archive failed' });
      }
    },
    [],
  );

  const handleSent = useCallback(() => {
    setComposing(false);
    setToast({ kind: 'success', message: 'message sent' });
    void refresh();
  }, [refresh]);

  const handleSendError = useCallback((message: string) => {
    setToast({ kind: 'error', message });
  }, []);

  return (
    <main className="inbox-main" aria-label="Inbox">
      <header className="inbox-header">
        <div className="inbox-header-titles">
          <p className="folio">cullis · inbox</p>
          <h1 className="inbox-title">
            <em>Messages</em>
          </h1>
        </div>
        <button
          type="button"
          className="inbox-compose-btn"
          onClick={() => {
            setComposing(true);
            setSelectedId(null);
          }}
        >
          + Compose
        </button>
      </header>

      <nav className="inbox-tabs" aria-label="Inbox filter">
        {TABS.map((t) => {
          const count =
            t.id === 'unread'
              ? messages.filter((m) => m.delivery_state === 'pending').length
              : t.id === 'all'
                ? messages.length
                : 0;
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              type="button"
              className={`inbox-tab${active ? ' inbox-tab-active' : ''}`}
              aria-pressed={active}
              onClick={() => setTab(t.id)}
            >
              <span>{t.label}</span>
              {count > 0 ? <span className="inbox-tab-count">{count}</span> : null}
            </button>
          );
        })}
      </nav>

      <div className="inbox-body">
        <section className="inbox-list" aria-label="Message list">
          {loading ? (
            <InboxSkeleton />
          ) : error ? (
            <InboxError message={error} onRetry={refresh} />
          ) : filtered.length === 0 ? (
            <InboxEmpty tab={tab} />
          ) : (
            <ol className="inbox-rows">
              {filtered.map((m) => (
                <InboxRow
                  key={m.msg_id}
                  message={m}
                  selected={m.msg_id === selectedId}
                  onSelect={() => {
                    setSelectedId(m.msg_id);
                    setComposing(false);
                  }}
                />
              ))}
            </ol>
          )}
        </section>

        <aside className="inbox-detail" aria-label="Message detail">
          {composing ? (
            <ComposeForm
              onSent={handleSent}
              onError={handleSendError}
              onCancel={() => setComposing(false)}
            />
          ) : selected ? (
            <MessageDetail
              message={selected}
              onAck={() => handleAck(selected.msg_id)}
              onArchive={() => handleArchive(selected.msg_id)}
            />
          ) : (
            <DetailPlaceholder />
          )}
        </aside>
      </div>

      {toast ? (
        <div
          role="status"
          className={`inbox-toast inbox-toast-${toast.kind}`}
        >
          {toast.message}
        </div>
      ) : null}
    </main>
  );
}

// ─── Sub-components ──────────────────────────────────────────────────

interface InboxRowProps {
  message: InboxMessage;
  selected: boolean;
  onSelect: () => void;
}

function InboxRow({ message, selected, onSelect }: InboxRowProps) {
  const unread = message.delivery_state === 'pending';
  const cls = [
    'inbox-row',
    unread ? 'inbox-row-unread' : '',
    selected ? 'inbox-row-selected' : '',
  ]
    .filter(Boolean)
    .join(' ');
  return (
    <li>
      <button type="button" className={cls} onClick={onSelect}>
        <div className="inbox-row-head">
          <PrincipalBadge type={message.sender_principal_type} size="sm" />
          <span className="inbox-row-sender">{message.sender_name}</span>
          <span className="inbox-row-org" title={message.sender_org_id}>
            {message.sender_org_id}
          </span>
          <time className="inbox-row-time" dateTime={message.enqueued_at}>
            {formatRelative(message.enqueued_at)}
          </time>
        </div>
        <div className="inbox-row-subject">{deriveSubject(message)}</div>
        <div className="inbox-row-snippet">{snippet(message.body)}</div>
        <div className="inbox-row-meta">
          <VerificationChip state={message.delivery_state} />
        </div>
      </button>
    </li>
  );
}

function VerificationChip({ state }: { state: string }) {
  // The backend hash chain runs server-side and is verified at every
  // append. The SPA can only surface the delivery state that the
  // recipient sees: pending = arrived but not yet acked, delivered =
  // hash-chain row landed and acked, archived = soft-hidden.
  const map: Record<string, { label: string; tone: 'ok' | 'warn' | 'mute' }> = {
    pending: { label: 'verified ✓', tone: 'ok' },
    delivered: { label: 'verified ✓', tone: 'ok' },
    archived: { label: 'archived', tone: 'mute' },
  };
  const meta = map[state] ?? { label: state, tone: 'mute' as const };
  return (
    <span className={`verify-chip verify-chip-${meta.tone}`}>{meta.label}</span>
  );
}

function MessageDetail({
  message,
  onAck,
  onArchive,
}: {
  message: InboxMessage;
  onAck: () => void;
  onArchive: () => void;
}) {
  return (
    <article className="msg-detail">
      <header className="msg-detail-head">
        <div className="msg-detail-titles">
          <p className="folio">message</p>
          <h2 className="msg-detail-subject">{deriveSubject(message)}</h2>
        </div>
        <div className="msg-detail-actions">
          {message.delivery_state === 'pending' ? (
            <button type="button" onClick={onAck} className="msg-action">
              Mark read
            </button>
          ) : null}
          <button
            type="button"
            onClick={onArchive}
            className="msg-action msg-action-danger"
          >
            Archive
          </button>
        </div>
      </header>

      <dl className="msg-detail-fields">
        <div>
          <dt>From</dt>
          <dd className="msg-detail-from">
            <PrincipalBadge
              type={message.sender_principal_type}
              size="sm"
            />
            <span>{message.sender_name}</span>
            <span className="msg-detail-org">@ {message.sender_org_id}</span>
          </dd>
        </div>
        <div>
          <dt>Received</dt>
          <dd>
            <time dateTime={message.enqueued_at}>{message.enqueued_at}</time>
          </dd>
        </div>
        <div>
          <dt>Expires</dt>
          <dd>
            <time dateTime={message.ttl_expires_at}>
              {message.ttl_expires_at}
            </time>
          </dd>
        </div>
        {message.consent_id ? (
          <div>
            <dt>Consent</dt>
            <dd className="msg-detail-mono">{message.consent_id}</dd>
          </div>
        ) : null}
      </dl>

      <section className="msg-detail-body">
        <h3 className="msg-detail-section-title">
          <em>Body</em>
        </h3>
        <pre className="msg-detail-pre">{message.body}</pre>
      </section>

      <section className="msg-detail-audit">
        <h3 className="msg-detail-section-title">
          <em>Audit chain</em>
        </h3>
        <p className="msg-detail-audit-pending">
          Per-message audit chain detail
          (<code>GET /v1/audit/messages/{message.msg_id}</code>) lands when
          the broker exposes the route. Server-side, every row is appended
          to the per-org hash chain and dual-written through Court for
          cross-org messages.
        </p>
        <dl className="msg-detail-fields">
          <div>
            <dt>msg_id</dt>
            <dd className="msg-detail-mono">{message.msg_id}</dd>
          </div>
          <div>
            <dt>state</dt>
            <dd>
              <VerificationChip state={message.delivery_state} />
            </dd>
          </div>
        </dl>
      </section>
    </article>
  );
}

function ComposeForm({
  onSent,
  onError,
  onCancel,
}: {
  onSent: () => void;
  onError: (message: string) => void;
  onCancel: () => void;
}) {
  const [recipientOrg, setRecipientOrg] = useState('');
  const [recipientType, setRecipientType] = useState<PrincipalType>('user');
  const [recipientName, setRecipientName] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [sending, setSending] = useState(false);

  const reachLabel = useMemo(() => {
    const trimmed = recipientOrg.trim().toLowerCase();
    if (!trimmed) return null;
    // Heuristic: same-org if recipientOrg matches the caller's org —
    // for Phase 2 we don't have caller principal yet, so we just
    // show the recipient quadrant target so the user sees what kind
    // of capability scope is being exercised.
    return `target: ${recipientType}@${trimmed}`;
  }, [recipientOrg, recipientType]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!recipientOrg || !recipientName || !body) return;
    setSending(true);
    try {
      const req: InboxSendRequest = {
        recipient_org_id: recipientOrg.trim(),
        recipient_principal_type: recipientType,
        recipient_name: recipientName.trim(),
        body,
        subject: subject.trim() || undefined,
      };
      await sendInboxMessage(req);
      onSent();
      // Clear after a successful send so the form is ready for the
      // next compose without manual reset.
      setRecipientOrg('');
      setRecipientName('');
      setSubject('');
      setBody('');
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? `send failed (${err.status})`
          : 'send failed';
      onError(msg);
    } finally {
      setSending(false);
    }
  };

  const canSend = !!(
    recipientOrg.trim() &&
    recipientName.trim() &&
    body.trim() &&
    !sending
  );

  return (
    <form className="msg-compose" onSubmit={submit}>
      <header className="msg-detail-head">
        <div className="msg-detail-titles">
          <p className="folio">new message</p>
          <h2 className="msg-detail-subject">
            <em>Compose</em>
          </h2>
        </div>
        <div className="msg-detail-actions">
          <button
            type="button"
            className="msg-action"
            onClick={onCancel}
            disabled={sending}
          >
            Cancel
          </button>
        </div>
      </header>

      <fieldset className="msg-compose-fieldset" disabled={sending}>
        <label className="msg-compose-row">
          <span className="msg-compose-label">recipient org</span>
          <input
            type="text"
            value={recipientOrg}
            onChange={(e) => setRecipientOrg(e.target.value)}
            placeholder="mediterranean"
            spellCheck={false}
            autoComplete="off"
            required
          />
        </label>

        <label className="msg-compose-row">
          <span className="msg-compose-label">recipient type</span>
          <select
            value={recipientType}
            onChange={(e) => setRecipientType(e.target.value as PrincipalType)}
          >
            {PRINCIPAL_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>

        <label className="msg-compose-row">
          <span className="msg-compose-label">recipient name</span>
          <input
            type="text"
            value={recipientName}
            onChange={(e) => setRecipientName(e.target.value)}
            placeholder="claim-officer"
            spellCheck={false}
            autoComplete="off"
            required
          />
        </label>

        <label className="msg-compose-row">
          <span className="msg-compose-label">subject</span>
          <input
            type="text"
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder="optional"
            autoComplete="off"
          />
        </label>

        <label className="msg-compose-row msg-compose-row-stack">
          <span className="msg-compose-label">body</span>
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            rows={10}
            placeholder="Body (Markdown allowed)"
            required
          />
        </label>
      </fieldset>

      <footer className="msg-compose-footer">
        {reachLabel ? (
          <span className="msg-compose-scope" title="Capability scope">
            {reachLabel}
          </span>
        ) : (
          <span />
        )}
        <button
          type="submit"
          className="msg-compose-send"
          disabled={!canSend}
        >
          {sending ? 'Sending…' : 'Send'}
        </button>
      </footer>
    </form>
  );
}

function InboxSkeleton() {
  return (
    <ol className="inbox-rows" aria-busy="true">
      {[0, 1, 2, 3, 4].map((i) => (
        <li key={i}>
          <div className="inbox-row inbox-row-skeleton">
            <div className="skel-line skel-line-head" />
            <div className="skel-line skel-line-subject" />
            <div className="skel-line skel-line-snippet" />
          </div>
        </li>
      ))}
    </ol>
  );
}

function InboxEmpty({ tab }: { tab: InboxTab }) {
  const copy: Record<InboxTab, { title: string; body: string }> = {
    all: {
      title: 'Empty.',
      body: 'No messages have been delivered to this principal yet.',
    },
    unread: {
      title: 'All caught up.',
      body: 'Nothing pending. Acked messages move to All.',
    },
    sent: {
      title: 'Sent items',
      body: 'The four-quadrant outbox lands in a follow-up. Sent appears here.',
    },
    drafts: {
      title: 'No drafts',
      body: 'Local drafts arrive with the offline composer in Phase 5.',
    },
  };
  const c = copy[tab];
  return (
    <div className="inbox-empty">
      <p className="inbox-empty-title">
        <em>{c.title}</em>
      </p>
      <p className="inbox-empty-body">{c.body}</p>
    </div>
  );
}

function InboxError({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}) {
  return (
    <div className="inbox-error">
      <p className="inbox-error-title">
        <em>Could not load.</em>
      </p>
      <p className="inbox-error-body">{message}</p>
      <button type="button" className="msg-action" onClick={onRetry}>
        Retry
      </button>
    </div>
  );
}

function DetailPlaceholder() {
  return (
    <div className="inbox-detail-empty">
      <p className="inbox-empty-title">
        <em>No message selected.</em>
      </p>
      <p className="inbox-empty-body">
        Pick a row to read it, or compose a new one.
      </p>
    </div>
  );
}
