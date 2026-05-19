import { useEffect, useState } from 'react';
import { listModels, type ModelsSource } from '../lib/api';
import { ensureSession } from '../lib/session-singleton';

const STORAGE_KEY = 'cullis-chat:model';
const FALLBACK_MODEL = 'claude-haiku-4-5';

/**
 * Read the user's selected model. ChatApp also reads this string at
 * `send()` time (no React state shared across islands — see comment
 * in `lib/session-singleton.ts`).
 */
export function readSelectedModel(): string {
  try {
    return window.localStorage.getItem(STORAGE_KEY) ?? FALLBACK_MODEL;
  } catch {
    return FALLBACK_MODEL;
  }
}

/**
 * Live model picker. Fetches `/v1/models` on mount; defaults to
 * the cached preference + the hard-coded fallback while loading.
 *
 * When the Ambassador couldn't reach Mastio it returns `source:
 * "fallback"` plus the compiled-in `advertised_models`. We surface
 * a warning so the user understands why "the model I configured
 * isn't in the dropdown".
 */
export default function ModelPicker() {
  const [models, setModels] = useState<string[]>([readSelectedModel(), FALLBACK_MODEL]);
  const [selected, setSelected] = useState<string>(readSelectedModel);
  const [loaded, setLoaded] = useState(false);
  const [source, setSource] = useState<ModelsSource>('live');
  const [fetchError, setFetchError] = useState<string | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        await ensureSession();
        const res = await listModels();
        if (cancelled) return;
        const ids = Array.from(new Set(res.data.map((m) => m.id)));
        if (ids.length > 0) setModels(ids);
        if (!ids.includes(selected) && ids.length > 0) {
          // Cached preference no longer offered — reset to first.
          setSelected(ids[0]);
          try {
            window.localStorage.setItem(STORAGE_KEY, ids[0]);
          } catch {
            /* ignore */
          }
        }
        setSource(res.source);
        setFetchError(res.error);
        setLoaded(true);
      } catch (err) {
        // Network-level failure (e.g. the ambassador itself is down).
        // The dropdown keeps its local fallback, but we still tell the
        // user the list is not authoritative.
        if (cancelled) return;
        setSource('fallback');
        setFetchError(err instanceof Error ? err.message : 'fetch failed');
        setLoaded(true);
      }
    })();
    return () => {
      cancelled = true;
    };
    // We intentionally don't depend on `selected` — initial cached read is enough.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function pick(id: string) {
    setSelected(id);
    try {
      window.localStorage.setItem(STORAGE_KEY, id);
    } catch {
      /* ignore */
    }
    document.dispatchEvent(new CustomEvent('cullis:model-changed', { detail: id }));
  }

  const isFallback = loaded && source === 'fallback';

  return (
    <label
      className="model-picker"
      data-loaded={loaded ? 'true' : 'false'}
      data-source={source}
    >
      <span className="folio">model</span>
      <select
        value={selected}
        onChange={(e) => pick(e.target.value)}
        aria-label="Active model"
      >
        {models.map((id) => (
          <option key={id} value={id}>{id}</option>
        ))}
      </select>
      {isFallback && (
        <span
          className="model-picker__fallback"
          role="status"
          aria-live="polite"
          title={
            fetchError
              ? `Cannot reach Mastio — live model list unavailable (${fetchError})`
              : 'Cannot reach Mastio — live model list unavailable'
          }
        >
          offline
        </span>
      )}
    </label>
  );
}
