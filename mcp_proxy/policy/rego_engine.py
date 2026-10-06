"""Embedded Rego policy engine — OPA WASM eval inside the Mastio process.

Operators write Rego policies in the dashboard Policies page; the
backend compiles them to a WebAssembly bundle via the ``opa`` CLI
shipped alongside the Mastio binary, persists the WASM blob next to
the source, and evaluates each policy decision in-process via
``opa-wasmtime``. No sidecar OPA daemon, no extra container, no
network hop on the decision hot path.

Two surfaces:

  * :func:`compile_rego` — synchronous subprocess invocation of the
    bundled ``opa build`` against a tempdir containing the operator's
    Rego source. Returns the resulting WASM bytes (extracted from the
    OPA bundle tarball). Raises :class:`RegoCompileError` on syntax /
    package errors, surfacing the operator-facing diagnostic message
    so the dashboard can render it inline.

  * :class:`RegoEngine` — wraps a compiled WASM bundle. ``evaluate``
    takes an arbitrary JSON-serialisable input and returns the policy
    decision dict the operator's Rego computes under
    ``data.cullis.policy.<surface>``. Thread-safe (the underlying
    ``OPAPolicy`` is re-instantiated per call so wasmtime instance
    state never leaks between evaluations).

Failure modes are explicitly fail-closed:

  * Compile error → :class:`RegoCompileError` — the dashboard surfaces
    the message; the previously saved policy remains active. If no policy
    was saved before, the legacy allowlist remains active.

  * Runtime error (WASM trap, malformed input, missing
    ``data.cullis.policy.<surface>`` rule) → the caller sees the
    exception and treats the decision as ``deny`` (the
    PDP / tool_call / policy_bridge handlers wrap the engine call so
    a runtime fault never returns a stale ``allow``).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import tarfile
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_log = logging.getLogger("mcp_proxy.policy.rego_engine")


# Operator can pin the ``opa`` binary location via env (containers
# bundle it at ``/usr/local/bin/opa``); the default search PATH covers
# developer machines where it lives on /usr/bin / /usr/local/bin.
_OPA_BINARY_ENV = "MCP_PROXY_OPA_BINARY"
_OPA_DEFAULT_PATHS = ("opa", "/usr/local/bin/opa", "/usr/bin/opa")

# Compile timeout — Rego is small; honest policies compile in < 1 s.
# 10 s guards against a wedged subprocess without making the dashboard
# Save button feel hung.
_COMPILE_TIMEOUT_SECONDS = 10.0


class RegoCompileError(RuntimeError):
    """Surface the ``opa build`` diagnostic to the operator."""


class RegoEvalError(RuntimeError):
    """Surface a runtime WASM eval fault to the caller."""


@dataclass(frozen=True)
class CompiledPolicy:
    """Compiled WASM bundle + the digest the cache keys on."""

    wasm: bytes
    sha256: str

    @classmethod
    def from_wasm(cls, wasm: bytes) -> "CompiledPolicy":
        digest = hashlib.sha256(wasm).hexdigest()
        return cls(wasm=wasm, sha256=digest)


def _resolve_opa_binary() -> str:
    """Find the ``opa`` binary, honouring ``MCP_PROXY_OPA_BINARY``.

    Raises :class:`RegoCompileError` (not FileNotFoundError) so the
    dashboard can surface the same error class for both
    binary-missing and compile-failed paths.
    """
    pinned = os.environ.get(_OPA_BINARY_ENV)
    candidates = (pinned,) if pinned else _OPA_DEFAULT_PATHS
    for cand in candidates:
        if not cand:
            continue
        # Honour absolute paths verbatim; fall back to PATH lookup for
        # the bare ``opa`` candidate.
        if os.path.isabs(cand):
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
            continue
        import shutil
        resolved = shutil.which(cand)
        if resolved:
            return resolved
    raise RegoCompileError(
        f"opa binary not found (looked at: {candidates}). Install OPA "
        f"on the Mastio host or pin the location via {_OPA_BINARY_ENV}.",
    )


_DEFAULT_ENTRYPOINTS = ("cullis/policy/session", "cullis/policy/tool_call")


def compile_rego(
    source: str,
    *,
    entrypoints: tuple[str, ...] = _DEFAULT_ENTRYPOINTS,
) -> CompiledPolicy:
    """Compile a Rego source string into a WASM bundle.

    Args:
        source: the Rego document the operator authored.
        entrypoints: slash-separated rule paths the WASM bundle must
            expose for evaluation. OPA v1.x requires each entrypoint
            to point at a concrete rule (the pre-v1 contract of
            "package root + drill at runtime" no longer holds). The
            defaults cover Cullis' two surfaces — ``cullis/policy/session``
            and ``cullis/policy/tool_call`` — so an operator's single
            Rego file with rules under both names compiles in one
            shot. The compile fails-closed if a declared entrypoint
            doesn't exist in the source (the operator sees the
            ``opa build`` diagnostic verbatim).

    Returns:
        A :class:`CompiledPolicy` carrying the raw WASM bytes (the
        caller persists them as a BLOB next to the source) and the
        SHA-256 digest (used as the cache key by :class:`RegoEngine`).

    Raises:
        RegoCompileError: any compile failure — surfaced with the
            ``opa build`` stderr so the dashboard can show the operator
            the exact line / column that failed.
    """
    opa = _resolve_opa_binary()
    with tempfile.TemporaryDirectory(prefix="cullis-rego-") as workdir:
        src_path = Path(workdir) / "policy.rego"
        src_path.write_text(source)
        bundle_path = Path(workdir) / "bundle.tar.gz"
        # Build the argv: one ``-e <entrypoint>`` per declared rule
        # plus the standard ``-t wasm`` target + ``-o`` output path.
        argv: list[str] = [opa, "build", "-t", "wasm"]
        for ep in entrypoints:
            argv.extend(("-e", ep))
        argv.extend(("-o", str(bundle_path), str(src_path)))
        try:
            result = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=_COMPILE_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RegoCompileError(
                f"opa build timed out after {_COMPILE_TIMEOUT_SECONDS}s",
            ) from exc

        if result.returncode != 0:
            # opa build writes diagnostics to stderr; preserve both
            # streams since some errors land on stdout.
            diag = (result.stderr or result.stdout or "").strip()
            raise RegoCompileError(
                diag or f"opa build exited with code {result.returncode}",
            )

        if not bundle_path.exists():
            raise RegoCompileError("opa build produced no bundle output")

        # The bundle is a tar.gz containing ``/policy.wasm`` (plus
        # data + manifest). Extract just the WASM blob.
        try:
            with tarfile.open(bundle_path, mode="r:gz") as tar:
                members = [m for m in tar.getmembers() if m.name.endswith(".wasm")]
                if not members:
                    raise RegoCompileError(
                        "opa build bundle contained no .wasm file",
                    )
                member = members[0]
                extracted = tar.extractfile(member)
                if extracted is None:
                    raise RegoCompileError(
                        f"opa build bundle entry {member.name} unreadable",
                    )
                wasm = extracted.read()
        except tarfile.TarError as exc:
            raise RegoCompileError(
                f"opa build bundle not a valid tar.gz: {exc}",
            ) from exc

    return CompiledPolicy.from_wasm(wasm)


_INSTANCE_CACHE: dict[str, Any] = {}
_INSTANCE_CACHE_LOCK = threading.Lock()
_INSTANCE_CACHE_MAX = 32  # operator policies rotate rarely; LRU-style trim is enough


def _build_opa_policy(wasm: bytes) -> Any:
    """Materialise the WASM bytes to disk and instantiate ``OPAPolicy``.

    Factored out so the cache hit path (below) can avoid the tempfile
    + native instantiation cost (~15-20ms on a modest dev laptop)
    every decision after the first.
    """
    try:
        from opa_wasmtime import OPAPolicy  # type: ignore
    except ImportError as exc:
        raise RegoEvalError(
            "opa-wasmtime is not installed — cannot evaluate WASM "
            "policy. Install ``opa-wasmtime`` in the Mastio image.",
        ) from exc

    with tempfile.NamedTemporaryFile(
        prefix="cullis-rego-", suffix=".wasm", delete=False,
    ) as tmp:
        tmp.write(wasm)
        tmp_path = tmp.name
    try:
        return OPAPolicy(tmp_path)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _get_cached_policy(wasm: bytes, sha256: str) -> Any:
    """Return a process-wide cached ``OPAPolicy`` for this WASM bundle.

    Cache key is the SHA-256 of the WASM bytes — when the operator
    saves a new Rego policy in the dashboard, the new bundle has a
    different hash and gets its own instance; the old one is evicted
    on the LRU trim below.

    Why module-level + ``threading.Lock`` and not ``asyncio.Lock``:

      * The wasmtime store / linker behind ``OPAPolicy`` is a native
        object with mutable internal state. Two concurrent calls into
        ``opa_policy.evaluate(...)`` on the same instance race on the
        store and can produce corrupt output (observed on opa-wasmtime
        0.1.1 + wasmtime 44.0.0 — the wasmtime engine is thread-safe
        but the store on top of it is not).

      * FastAPI under uvicorn runs the request handlers on the asyncio
        event loop. ``OPAPolicy.evaluate`` is synchronous; if two
        in-flight requests hit the same cached instance in the same
        event loop iteration, they would NOT actually overlap (the
        event loop is single-threaded). The lock is here as
        defence-in-depth for the day someone moves the eval onto a
        thread pool via ``asyncio.to_thread`` — the cost on the
        single-threaded hot path is one un-contended mutex
        acquisition (~tens of ns).
    """
    # Fast path — read under lock so the cache map is consistent.
    with _INSTANCE_CACHE_LOCK:
        cached = _INSTANCE_CACHE.get(sha256)
        if cached is not None:
            return cached

    # Slow path — instantiate outside the lock (native I/O), then
    # re-check + insert. The double-check avoids two threads racing to
    # build for the same hash.
    fresh = _build_opa_policy(wasm)
    with _INSTANCE_CACHE_LOCK:
        if sha256 in _INSTANCE_CACHE:
            return _INSTANCE_CACHE[sha256]
        # Trim oldest entries when the cache fills. A real LRU would be
        # cleaner but operator policies rotate at human pace, not per-
        # request — a simple FIFO trim under the cap is enough.
        if len(_INSTANCE_CACHE) >= _INSTANCE_CACHE_MAX:
            for k in list(_INSTANCE_CACHE.keys())[:-_INSTANCE_CACHE_MAX + 1]:
                _INSTANCE_CACHE.pop(k, None)
        _INSTANCE_CACHE[sha256] = fresh
        return fresh


def _reset_instance_cache() -> None:
    """Test hook — clear the process-wide cache between unit tests."""
    with _INSTANCE_CACHE_LOCK:
        _INSTANCE_CACHE.clear()


class RegoEngine:
    """Evaluate a compiled WASM policy against an arbitrary input.

    Performance characteristics:

      * **First evaluate per WASM bundle** — instantiates an
        ``OPAPolicy`` (writes a tempfile + native wasmtime engine
        startup), takes ~15-25ms on modest hardware.

      * **Subsequent evaluates of the same bundle** — re-uses the
        cached instance via :func:`_get_cached_policy`. Hot-path
        latency drops to ~100µs (the cost of the
        :meth:`OPAPolicy.evaluate` JSON serialisation + WASM call).

    The cache key is the SHA-256 of the compiled WASM bytes — when
    the operator saves a new Rego policy in the dashboard, the new
    bundle has a different hash and gets its own instance; the old
    one is evicted on the LRU trim. Operators on the dashboard never
    see a stale decision.

    Thread-safety: ``OPAPolicy.evaluate`` on a single store is NOT
    safe under concurrent native invocation. The cache guards the
    instance lookup with a ``threading.Lock`` so the map stays
    consistent, but a per-instance lock is left out today because
    FastAPI under uvicorn runs handlers on a single-threaded asyncio
    loop and the eval is synchronous — two in-flight requests never
    overlap on the same instance in that runtime model. A future PR
    that moves eval onto ``asyncio.to_thread`` should add a
    per-instance lock here.
    """

    def __init__(self, policy: CompiledPolicy):
        self._policy = policy

    @property
    def sha256(self) -> str:
        return self._policy.sha256

    def evaluate(self, input_doc: Any, *, entrypoint: str = "cullis/policy") -> Any:
        """Run the policy against ``input_doc`` and return the result.

        The Rego is expected to compute the decision document at
        ``data.cullis.policy.<surface>`` so the operator can write
        rules for both ``session`` and ``tool_call`` in one Rego file
        with separate rules per surface. ``entrypoint`` selects which
        sub-document the WASM eval returns.

        Args:
            input_doc: any JSON-serialisable input (typically the OPA
                ``input`` dict that the caller would otherwise pass via
                the OPA Data API HTTP endpoint).
            entrypoint: the slash-separated package path to evaluate.
                Default ``cullis/policy`` returns the entire policy
                document; pass ``cullis/policy/session`` /
                ``cullis/policy/tool_call`` to drill into one surface.

        Returns:
            The decoded JSON result (typically a dict with
            ``decision`` + ``reason``).

        Raises:
            RegoEvalError: any WASM trap, JSON decode failure, or
                wasmtime startup error. Callers MUST treat this as a
                deny.
        """
        # Cache hit on the second+ evaluate of the same WASM bundle —
        # the cost of the OPAPolicy instantiation (tempfile +
        # wasmtime engine startup) is amortised across every decision
        # that runs against this operator policy version.
        try:
            opa_policy = _get_cached_policy(
                self._policy.wasm, self._policy.sha256,
            )
        except RegoEvalError:
            raise
        except Exception as exc:
            raise RegoEvalError(
                f"OPAPolicy instantiation failed: {exc}",
            ) from exc

        try:
            # opa-wasmtime's evaluate accepts a dict; it JSON-serialises
            # internally and returns the decoded result.
            result = opa_policy.evaluate(input_doc, entrypoint=entrypoint)
        except Exception as exc:
            raise RegoEvalError(
                f"WASM eval failed for entrypoint={entrypoint}: {exc}",
            ) from exc

        # opa-wasmtime returns ``[{"result": <document>}]`` per the OPA
        # WASM ABI contract. Unwrap so callers see the document
        # directly. When the policy has no opinion (rule undefined),
        # the result is an empty list — surface as ``None``.
        if isinstance(result, list):
            if not result:
                return None
            head = result[0]
            if isinstance(head, dict) and "result" in head:
                return head["result"]
            return head
        return result


def evaluate_decision(
    policy: CompiledPolicy,
    input_doc: dict,
    *,
    entrypoint: str = "cullis/policy",
) -> dict:
    """Convenience: evaluate + normalise to the dashboard decision shape.

    Rego authors are free to return any shape under
    ``data.cullis.policy.<surface>``; the Mastio dashboard + the OPA
    Data API endpoint expect ``{"decision": "allow"|"deny",
    "reason": str?}``. This helper coerces the common shapes:

      * Boolean ``true`` → ``{"decision": "allow"}``
      * Boolean ``false`` → ``{"decision": "deny"}``
      * Dict with ``decision`` key → returned as-is (with ``reason``
        coerced to string if non-empty)
      * Anything else → ``RegoEvalError`` (so the caller fails-closed)

    Returns a dict guaranteed to carry ``decision``.
    """
    engine = RegoEngine(policy)
    result = engine.evaluate(input_doc, entrypoint=entrypoint)

    if result is True:
        return {"decision": "allow"}
    if result is False:
        return {"decision": "deny"}
    if isinstance(result, dict):
        decision = result.get("decision")
        if decision in {"allow", "deny"}:
            out = {"decision": decision}
            reason = result.get("reason")
            if reason:
                out["reason"] = str(reason)
            return out
    raise RegoEvalError(
        f"Rego policy returned unexpected shape: {json.dumps(result)[:200]} "
        f"— expected boolean or {{decision, reason}} dict.",
    )
