# inference image. The trained model is mounted at /app/artifacts
# (see docker-compose.yml); without a complete model the service exits with code 2.
# Same Python minor as the training host: the model is a pickle of River objects.
FROM python:3.14-slim

WORKDIR /app
RUN useradd --create-home --uid 10001 app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY training ./training
COPY config.yaml ./

USER app
ENV PYTHONUNBUFFERED=1 \
    INFERENCE_CONFIG=/app/config.yaml

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-m", "inference.healthcheck"]
CMD ["python", "-m", "inference"]
