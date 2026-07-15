FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install .

USER 65532:65532
EXPOSE 8000
ENTRYPOINT ["sentinelops"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]

