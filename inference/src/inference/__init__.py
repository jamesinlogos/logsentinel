"""LogSentinel ransomware detection service (see ../inference/README.md)."""

__version__ = "0.1.0"

PRODUCT = "logsentinel"
"""Vendor namespace of every non-ECS field and the ``event.module`` of every document."""
SERVICE_NAME = "inference"
ECS_VERSION = "8.0.0"
"""ECS release whose field names and meanings the documents and log records follow."""
