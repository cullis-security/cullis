import { useChat } from '../lib/chat-context';
import { parseSpiffe } from '../lib/principal';
import type { AuditTrace, ChatMessage, PrincipalType } from '../lib/types';

/**
 * AuditPanel — right rail. Reads messages from chat context and
 * renders one entry per assistant turn that has an audit anchor.
 *
 * Cross-highlight: clicking an entry sets `selectedMessageId`; the
 * matching message in the chat highlights with a temporary border
 * (handled by ChatWindow / Message via the same context).
 */
export function AuditPanel() {
  const { messages, selectedMessageId, selectMessage } = useChat();

  const traced = messages.filter(
    (m): m is ChatMessage & { audit: AuditTrace } => m.role === 'assistant' && !!m.audit,
  );

  return (
    <aside className="audit-pane" aria-label="Audit chain">
      <header className="ap-head">
        <span className="eyebrow">audit chain</span>
        <span className="ap-state">
          <span className="pulse-dot" aria-hidden="true" />
          <span className="ap-state-label">live</span>
        </span>
      </header>

      <div className="ap-body">
        {traced.length === 0 ? <AuditEmpty /> : null}

        {traced.map((m) => (
          <AuditEntry
            key={m.id}
            message={m}
            audit={m.audit}
            selected={selectedMessageId === m.id}
            onClick={() => selectMessage(selectedMessageId === m.id ? null : m.id)}
          />
        ))}
      </div>

      <footer className="ap-foot folio">
        ADR-019 §4 · ADR-020 <em>principal_type</em>
      </footer>
    </aside>
  );
}

function AuditEmpty() {
  return (
    <>
      <p className="ap-empty">
        No turns yet. <br />
        Each assistant message will append a row here with its
        <em> trace_id</em>, latency, tool calls, and the corresponding
        Mastio audit anchor.
      </p>
      <dl className="ap-meta">
        <dt>chain</dt>
        <dd>append-only</dd>
        <dt>anchor</dt>
        <dd>Mastio · TSA</dd>
        <dt>signing</dt>
        <dd>DPoP+mTLS · ES256</dd>
        <dt>endpoint</dt>
        <dd><code>/v1/chat/completions</code></dd>
      </dl>
    </>
  );
}

interface EntryProps {
  message: ChatMessage;
  audit: AuditTrace;
  selected: boolean;
  onClick: () => void;
}

function AuditEntry({ message, audit, selected, onClick }: EntryProps) {
  const ts = new Date(message.createdAt);
  const tsLabel = ts.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  const principal = audit.principal?.spiffe_id ? parseSpiffe(audit.principal.spiffe_id) : null;
  const principalType: PrincipalType =
    audit.principal?.principal_type ?? principal?.principal_type ?? 'agent';
  const principalName = principal?.name ?? 'unknown';

  return (
    <button
      type="button"
      className={`audit-entry${selected ? ' is-selected' : ''}`}
      onClick={onClick}
      aria-pressed={selected}
      aria-label={`Audit row for trace ${audit.trace_id}`}
    >
      <header className="ae-head">
        <span className="ae-folio">
          <em>{tsLabel}</em>
        </span>
        <span className="ae-trace">{audit.trace_id}</span>
      </header>

      <dl className="ae-meta">
        <dt>latency</dt>
        <dd>{audit.latency_ms} ms</dd>

        <dt>principal</dt>
        <dd className="ae-principal">
          <em>{principalType}</em><span className="ae-sep">·</span>{principalName}
        </dd>

        {audit.tools.length > 0 ? (
          <>
            <dt>tools</dt>
            <dd>
              <ul className="ae-tools">
                {audit.tools.map((t, i) => (
                  <li key={`${audit.trace_id}-${t.name}-${i}`}>
                    <code>{t.name}</code>
                    {t.latency_ms !== undefined ? <span className="ae-tool-latency">{t.latency_ms} ms</span> : null}
                  </li>
                ))}
              </ul>
            </dd>
          </>
        ) : null}

        <dt>anchor</dt>
        <dd>Mastio audit chain</dd>
      </dl>
    </button>
  );
}
