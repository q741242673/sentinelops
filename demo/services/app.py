from __future__ import annotations

import logging
import os
import time
from itertools import count

import httpx
from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse
from opentelemetry import trace
from opentelemetry._logs import set_logger_provider
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

SERVICE_NAME = os.getenv("SERVICE_NAME", "order-service")
SERVICE_ROLE = os.getenv("SERVICE_ROLE", "order")
INVENTORY_URL = os.getenv("INVENTORY_URL", "http://inventory-service:8000")
FAIL_EVERY = max(int(os.getenv("FAIL_EVERY", "3")), 0)
OTLP_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4318").rstrip("/")

resource = Resource.create(
    {
        "service.name": SERVICE_NAME,
        "service.namespace": "sentinelops-demo",
        "deployment.environment.name": "kind",
    }
)

tracer_provider = TracerProvider(resource=resource)
tracer_provider.add_span_processor(
    BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{OTLP_ENDPOINT}/v1/traces"))
)
trace.set_tracer_provider(tracer_provider)

logger_provider = LoggerProvider(resource=resource)
logger_provider.add_log_record_processor(
    BatchLogRecordProcessor(OTLPLogExporter(endpoint=f"{OTLP_ENDPOINT}/v1/logs"))
)
set_logger_provider(logger_provider)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s level=%(levelname)s service=%(name)s message=%(message)s",
)
logger = logging.getLogger(SERVICE_NAME)
logger.addHandler(LoggingHandler(level=logging.INFO, logger_provider=logger_provider))

REQUESTS = Counter(
    "http_requests_total",
    "HTTP requests handled by the demo service",
    ["service", "route", "status"],
)
LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration for the demo service",
    ["service", "route"],
)
inventory_requests = count(1)
tracer = trace.get_tracer(__name__)
app = FastAPI(title=f"SentinelOps {SERVICE_NAME}")


@app.middleware("http")
async def record_request(request, call_next):
    started = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        route = request.url.path
        REQUESTS.labels(service=SERVICE_NAME, route=route, status=str(status)).inc()
        LATENCY.labels(service=SERVICE_NAME, route=route).observe(time.perf_counter() - started)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE_NAME}


@app.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/reserve")
async def reserve() -> JSONResponse:
    sequence = next(inventory_requests)
    if FAIL_EVERY and sequence % FAIL_EVERY == 0:
        logger.error("inventory_reservation_failed sequence=%s reason=synthetic_timeout", sequence)
        return JSONResponse(
            status_code=503,
            content={"status": "unavailable", "sequence": sequence},
        )
    logger.info("inventory_reserved sequence=%s", sequence)
    return JSONResponse(content={"status": "reserved", "sequence": sequence})


@app.post("/checkout")
async def checkout() -> JSONResponse:
    if SERVICE_ROLE != "order":
        return JSONResponse(status_code=404, content={"error": "not_order_service"})
    with tracer.start_as_current_span("checkout-workflow") as span:
        try:
            async with httpx.AsyncClient(timeout=2) as client:
                inventory = await client.post(f"{INVENTORY_URL}/reserve")
            trace_id = f"{span.get_span_context().trace_id:032x}"
            if inventory.status_code >= 500:
                logger.error(
                    "checkout_failed trace_id=%s downstream_status=%s",
                    trace_id,
                    inventory.status_code,
                )
                return JSONResponse(
                    status_code=502,
                    content={"status": "failed", "trace_id": trace_id},
                )
            logger.info("checkout_completed trace_id=%s", trace_id)
            return JSONResponse(content={"status": "completed", "trace_id": trace_id})
        except httpx.HTTPError as exc:
            trace_id = f"{span.get_span_context().trace_id:032x}"
            logger.exception("checkout_exception trace_id=%s error=%s", trace_id, exc)
            return JSONResponse(
                status_code=502,
                content={"status": "failed", "trace_id": trace_id},
            )


FastAPIInstrumentor.instrument_app(app, tracer_provider=tracer_provider)
HTTPXClientInstrumentor().instrument(tracer_provider=tracer_provider)
