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
    subfunction: int | None = None,
) -> TransactionRecord:
    """FC 08 and FC 43 records carry no address or quantity, as ingest builds
    them (D13); pass subfunction for those."""
    addressless = fc in (8, 43)
    return TransactionRecord(
        request_ts=ts,
        response_ts=ts + 0.05,
        server_ip=ip,
        unit_id=unit,
        function_code=fc,
        is_write=fc in (5, 6, 15, 16),
        is_exception=exc is not None,
        exception_code=exc,
        start_address=None if addressless else start,
        quantity=None if fc in (5, 6) or addressless else qty,
        value=None,
        subfunction=subfunction,
    )
