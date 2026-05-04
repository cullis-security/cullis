import type { ToolCallEvent } from '../lib/types';

interface Props {
  call: ToolCallEvent;
}

/**
 * Inline marginalia chip surfacing a tool call associated with the
 * current assistant turn. Pulse-dot while pending, solid + check +
 * latency once `tool_call_end` lands.
 */
export function ToolCallIndicator({ call }: Props) {
  const isPending = call.status === 'pending';
  return (
    <div className={`tool-chip ${isPending ? 'tool-chip-pending' : 'tool-chip-done'}`} role="status">
      <span className={isPending ? 'tool-dot tool-dot-pulsing' : 'tool-dot'} aria-hidden="true" />
      <span className="tool-name">
        {isPending ? <>calling <code>{call.name}</code></> : <>resolved <code>{call.name}</code></>}
      </span>
      {!isPending && call.latency_ms !== undefined ? (
        <span className="tool-latency">{call.latency_ms} ms</span>
      ) : null}
    </div>
  );
}
