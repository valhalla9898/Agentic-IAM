"""Prometheus metrics and OpenTelemetry initialization helpers."""

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
from prometheus_client import Counter, start_http_server

# Basic Prometheus metrics
REQUEST_COUNTER = Counter("agentic_iam_requests_total", "Total requests to Agentic-IAM")


def start_metrics_server(port: int = 8001):
    try:
        start_http_server(port)
    except OSError as e:
        import logging

        logging.getLogger(__name__).debug("Failed to start metrics server on port %s: %s", port, e)


def init_tracing():
    try:
        provider = TracerProvider()
        processor = SimpleSpanProcessor(ConsoleSpanExporter())
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)
    except Exception as e:
        import logging

        logging.getLogger(__name__).debug("Failed to initialize tracing: %s", e)
