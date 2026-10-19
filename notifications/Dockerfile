FROM python:3.14-slim

WORKDIR /app
RUN useradd --create-home --uid 10001 app
COPY src/notifications ./notifications
USER app
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-m", "notifications", "--healthcheck"]
CMD ["python", "-m", "notifications"]

