/**
 * Clipboard write with a textarea-based fallback for non-secure contexts.
 *
 * `navigator.clipboard.writeText` requires a secure context (HTTPS or
 * localhost). Cullis Chat is occasionally deployed behind an internal
 * reverse proxy without TLS terminating where the browser thinks; the
 * fallback uses the legacy `document.execCommand('copy')` against a
 * hidden textarea, which most browsers still honour from user gestures.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  if (typeof navigator !== 'undefined' && navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // fall through to legacy path
    }
  }

  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '0';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}
