"""Consumer group lag parsing."""

from __future__ import annotations

from sentinelbench.query_components import _parse_group_lag


def test_parse_group_lag_sums_partitions() -> None:
    text = """
GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG CONSUMER-ID HOST CLIENT-ID
inference telemetry.windows.normalized 0 10 12 2 cid /h rdkafka
inference telemetry.windows.normalized 1 5 5 0 cid /h rdkafka
inference telemetry.windows.normalized 2 - 0 - cid /h rdkafka
"""
    parsed = _parse_group_lag(text)
    assert parsed["lag_total"] == 2
    assert parsed["partitions"] == 3
    assert parsed["no_offset"] == 1


def test_parse_group_lag_empty() -> None:
    assert _parse_group_lag(None)["lag_total"] is None
    assert _parse_group_lag("")["partitions"] == 0
