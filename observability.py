"""Prometheus metrics and OpenTelemetry initialization helpers."""
import os
from prometheus_client import Counter, start_http_server
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

# Basic Prometheus metrics
REQUEST_COUNTER = Counter('agentic_iam_requests_total', 'Total requests to Agentic-IAM')


def start_metrics_server(port: int = 8001):
    try:
        start_http_server(port)
    except Exception:
        pass


def init_tracing():
    try:
        provider = TracerProvider()
        processor = SimpleSpanProcessor(ConsoleSpanExporter())
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)
    except Exception:
        pass
