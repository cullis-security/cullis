"""
OpenTelemetry bootstrap — tracer, meter, and initialization.

Usage anywhere in the app:
    from app.telemetry import tracer, meter

The module exports a no-op tracer/meter if OTel is disabled or if
the SDK fails to initialize (graceful degradation).
"""
import logging

from opentelemetry import trace, metrics

_log = logging.getLogger("agent_trust")

# Always importable. Before init_telemetry() these are no-op instances.
tracer: trace.Tracer = trace.get_tracer("agent_trust")
meter: metrics.Meter = metrics.get_meter("agent_trust")

_initialized = False


def init_telemetry() -> None:
    """
    Configure the OTel SDK, exporter, and auto-instrumentors.
    Called once from the lifespan. Idempotent.
    """
    global tracer, meter, _initialized
    if _initialized:
        return

    from app.config import get_settings
    settings = get_settings()

    if not settings.otel_enabled:
        _log.info("OpenTelemetry disabled (OTEL_ENABLED=false)")
        _initialized = True
        return

    try:
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

        resource = Resource.create({SERVICE_NAME: settings.otel_service_name})

        # ── Traces ────────────────────────────────────────────────
        span_exporter = OTLPSpanExporter(
            endpoint=settings.otel_exporter_otlp_endpoint,
            insecure=True,
        )
        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
        trace.set_tracer_provider(tracer_provider)
        tracer = trace.get_tracer("agent_trust")

        # ── Metrics ───────────────────────────────────────────────
        metric_exporter = OTLPMetricExporter(
            endpoint=settings.otel_exporter_otlp_endpoint,
            insecure=True,
        )
        metric_reader = PeriodicExportingMetricReader(
            metric_exporter,
            export_interval_millis=settings.otel_metrics_export_interval_ms,
        )
        meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        metrics.set_meter_provider(meter_provider)
        meter = metrics.get_meter("agent_trust")

        # ── Auto-instrumentation ──────────────────────────────────
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        from opentelemetry.instrumentation.redis import RedisInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        SQLAlchemyInstrumentor().instrument()
        RedisInstrumentor().instrument()
        HTTPXClientInstrumentor().instrument()

        _initialized = True
        _log.info(
            "OpenTelemetry initialized: service=%s endpoint=%s",
            settings.otel_service_name,
            settings.otel_exporter_otlp_endpoint,
        )

    except Exception:
        _log.warning("OpenTelemetry init failed — running without telemetry", exc_info=True)
        _initialized = True


def shutdown_telemetry() -> None:
    """Flush pending spans/metrics. Called from lifespan shutdown."""
    try:
        provider = trace.get_tracer_provider()
        if hasattr(provider, "shutdown"):
            provider.shutdown()
        m_provider = metrics.get_meter_provider()
        if hasattr(m_provider, "shutdown"):
            m_provider.shutdown()
    except Exception:
        _log.warning("OpenTelemetry shutdown error", exc_info=True)
