"""Shared hand-built TransactionRecord helper for baseline and detection tests.

Moved unchanged from tests/test_baseline.py. Records built here skip the pcap
layer, so tests can set exact timestamps (poll statistics, the 72 h window)
and exact address ranges. All values are synthetic.
"""

from pcap_builder import SERVER

from modbus_sentinel.ingest import TransactionRecord


def rec(
    ts: float,
    fc: int = 3,
    start: int = 100,
    qty: int = 10,
    unit: int = 1,
    ip: str = SERVER,
    exc: int | None = None,
) -> TransactionRecord:
    return TransactionRecord(
        request_ts=ts,
        response_ts=ts + 0.05,
        server_ip=ip,
        unit_id=unit,
        function_code=fc,
        is_write=fc in (5, 6, 15, 16),
        is_exception=exc is not None,
        exception_code=exc,
        start_address=start,
        quantity=None if fc in (5, 6) else qty,
        value=None,
    )
