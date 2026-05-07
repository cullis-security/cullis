/**
 * PrincipalBadge — shared chip for the three ADR-020 principal types.
 *
 * Single component used wherever a principal is rendered: inbox sender,
 * dashboard tables, audit log rows, identity panel. Color comes from
 * design tokens declared in `styles/tokens.css` (mirror of
 * `site/global.css`):
 *
 *   --cullis-badge-user      #3b7af5
 *   --cullis-badge-agent     #8b5cf6
 *   --cullis-badge-workload  #10b981
 *
 * Pure presentational, no state, no fetches.
 */
import type { PrincipalType } from '../../lib/types';

interface Props {
  type: PrincipalType;
  /** Compact: 9px font for tight rows. Default 10px. */
  size?: 'sm' | 'md';
  className?: string;
}

const LABELS: Record<PrincipalType, string> = {
  user: 'User',
  agent: 'Agent',
  workload: 'Workload',
};

export default function PrincipalBadge({ type, size = 'md', className }: Props) {
  const cls = ['principal-badge', `principal-badge-${type}`];
  if (size === 'sm') cls.push('principal-badge-sm');
  if (className) cls.push(className);
  return <span className={cls.join(' ')}>{LABELS[type]}</span>;
}
