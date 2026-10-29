"""Gate 1 ingest tests: direction attribution (D10) + pairing (D11).

Fixtures are synthetic pcaps built with scapy (D9: technique reused from
pcap-analyser's generate_test_pcaps.py pattern). Every locked D10/D11 behavior
gets a test, including the exception-response pairing positive control that
D11 requires: the wire FC differs from the request FC there, and a naive
wire-byte equality check silently drops it.
"""

from pathlib import Path

import pytest
from pcap_builder import (
    CLIENT,
    SERVER,
    Conn,
    exc_resp,
    frame,
    read_req,
    read_resp,
    write_single_req,
)
from scapy.layers.inet import TCP
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap, wrpcap

from modbus_sentinel.ingest import IngestResult, ingest_pcap


def ingest(tmp_path: Path, *conns: Conn) -> IngestResult:
    pkts = [p for c in conns for p in c.pkts]
    path = tmp_path / "fixture.pcap"
    wrpcap(str(path), pkts)
    return ingest_pcap(str(path))


# --- clean pairing -----------------------------------------------------------


def test_clean_read_cycle(tmp_path: Path) -> None:
    c = Conn()
    c.send(read_req(tid=1, addr=100, qty=10))
    c.recv(read_resp(tid=1, qty=10))
    result = ingest(tmp_path, c)
    assert result.anomalies == []
    (rec,) = result.records
    assert rec.server_ip == SERVER
    assert rec.unit_id == 1
    assert rec.function_code == 3
    assert rec.start_address == 100
    assert rec.quantity == 10
    assert not rec.is_write
    assert not rec.is_exception
    assert rec.request_ts < rec.response_ts  # canonical ts = request (D11)


def test_write_single_cycle(tmp_path: Path) -> None:
    c = Conn()
    c.send(write_single_req(tid=2, addr=40, value=7))
    c.recv(write_single_req(tid=2, addr=40, value=7))  # FC6 response echoes
    result = ingest(tmp_path, c)
    assert result.anomalies == []
    (rec,) = result.records
    assert rec.is_write and rec.function_code == 6
    assert rec.start_address == 40 and rec.value == 7


def test_exception_response_pairs_as_record(tmp_path: Path) -> None:
    """D11 required positive control: wire FC = request FC | 0x80 must PAIR.

    A wire-byte FC equality check silently kicks every legitimate exception
    into pairing_mismatch; this fixture is what makes that failure loud.
    """
    c = Conn()
    c.send(read_req(tid=9, fc=3))
    c.recv(exc_resp(tid=9, fc=3, code=2))  # illegal data address
    result = ingest(tmp_path, c)
    assert result.anomalies == []  # NOT pairing_mismatch, NOT orphans
    (rec,) = result.records
    assert rec.is_exception
    assert rec.exception_code == 2
    assert rec.function_code == 3


def test_exception_bit_on_request_never_pairs(tmp_path: Path) -> None:
    """End-to-end guard for the D11 round-6 concern: a crafted request with
    the exception bit set (wire fc=0x83) must NEVER produce a
    TransactionRecord, even when a genuine fc-3 response arrives with the
    same tid/unit. The parse-layer guard (test_corpus / test_mbap) proves
    0x83 is flagged, not laundered; this proves the consequence at the
    pairing layer: the crafted request never enters the outstanding table,
    so the real response is an orphan, not a corrupted record.
    """
    c = Conn()
    c.send(frame(1, 1, b"\x83\x02"))  # crafted "exception" on the request side
    c.recv(read_resp(tid=1))  # genuine fc-3 response, same tid/unit
    result = ingest(tmp_path, c)
    assert result.records == []  # the corruption scenario: must be impossible
    kinds = result.anomaly_counts()
    assert kinds.get("unknown_function_code") == 1  # crafted request flagged
    assert kinds.get("orphan_response") == 1  # response found nothing to pair with


# --- orphans, mismatch, tid reuse (D11) --------------------------------------


def test_unanswered_request_is_orphan(tmp_path: Path) -> None:
    c = Conn()
    c.send(read_req(tid=1))
    result = ingest(tmp_path, c)
    assert result.records == []
    (a,) = result.anomalies
    assert a.kind == "orphan_request" and "unanswered" in a.detail


def test_unsolicited_response_is_orphan(tmp_path: Path) -> None:
    c = Conn()
    c.recv(read_resp(tid=1))
    result = ingest(tmp_path, c)
    assert result.records == []
    (a,) = result.anomalies
    assert a.kind == "orphan_response"


def test_fc_mismatch_counted_not_paired(tmp_path: Path) -> None:
    c = Conn()
    c.send(read_req(tid=1, fc=3))
    c.recv(read_resp(tid=1, fc=4))  # response FC 4 to an FC 3 request
    result = ingest(tmp_path, c)
    assert result.records == []
    (a,) = result.anomalies
    assert a.kind == "pairing_mismatch"


def test_tid_reuse_orphans_old_request(tmp_path: Path) -> None:
    c = Conn()
    c.send(read_req(tid=1, addr=100))
    c.send(read_req(tid=1, addr=200))  # same key while unanswered
    c.recv(read_resp(tid=1))
    result = ingest(tmp_path, c)
    (rec,) = result.records
    assert rec.start_address == 200  # new request took the slot
    (a,) = result.anomalies
    assert a.kind == "orphan_request" and "tid_reuse" in a.detail


def test_outstanding_table_at_cap_counts_request_not_tracked(tmp_path: Path, monkeypatch) -> None:
    """D11 state cap. The real cap is 65536 (the transaction-id space); it is
    lowered to 2 here so the branch runs on three requests. The third request
    is counted as state_overflow and never tracked, so its response finds
    nothing to pair with, while the two requests already tracked still pair."""
    monkeypatch.setattr("modbus_sentinel.ingest.OUTSTANDING_CAP", 2)
    c = Conn()
    c.send(read_req(tid=1, addr=100))
    c.send(read_req(tid=2, addr=200))
    c.send(read_req(tid=3, addr=300), at=1001.0)
    c.recv(read_resp(tid=1))
    c.recv(read_resp(tid=2))
    c.recv(read_resp(tid=3))
    result = ingest(tmp_path, c)
    assert sorted(r.start_address for r in result.records) == [100, 200]
    overflow, orphan = result.anomalies
    assert overflow.kind == "state_overflow"
    assert overflow.detail == "outstanding-request table at cap 2; request tid=3 unit=1 counted, not tracked"
    assert overflow.timestamp == 1001.0
    assert orphan.kind == "orphan_response"
    assert orphan.detail == "response tid=3 unit=1 with no outstanding request"


def test_unit_id_in_pairing_key(tmp_path: Path) -> None:
    """Gateway multiplexing: same TID, different units must pair separately."""
    c = Conn()
    c.send(read_req(tid=1, unit=1, addr=100))
    c.send(read_req(tid=1, unit=2, addr=200))
    c.recv(read_resp(tid=1, unit=2))
    c.recv(read_resp(tid=1, unit=1))
    result = ingest(tmp_path, c)
    assert result.anomalies == []
    assert {(r.unit_id, r.start_address) for r in result.records} == {(1, 100), (2, 200)}


# --- segmentation (D2) --------------------------------------------------------


def test_pipelined_adus_one_segment(tmp_path: Path) -> None:
    c = Conn()
    c.send(read_req(tid=1) + read_req(tid=2) + read_req(tid=3))
    c.recv(read_resp(tid=1) + read_resp(tid=2) + read_resp(tid=3))
    result = ingest(tmp_path, c)
    assert result.anomalies == []
    assert len(result.records) == 3


def test_adu_split_across_segments_pairs(tmp_path: Path) -> None:
    req = read_req(tid=1)
    c = Conn()
    c.send(req[:5])
    c.send(req[5:])
    c.recv(read_resp(tid=1))
    result = ingest(tmp_path, c)
    assert result.anomalies == []
    assert len(result.records) == 1


def test_pure_retransmission_not_double_fed(tmp_path: Path) -> None:
    c = Conn()
    p = c.send(read_req(tid=1))
    c.send(read_req(tid=1), seq=p[TCP].seq)  # exact retransmit, same seq
    c.recv(read_resp(tid=1))
    result = ingest(tmp_path, c)
    assert result.anomalies == []  # no tid_reuse: bytes deduplicated, not re-parsed
    assert len(result.records) == 1
    assert result.retransmitted_segments == 1
    assert result.retransmitted_bytes == len(read_req(tid=1))  # full payload tallied


def test_partial_overlap_trim_is_counted(tmp_path: Path) -> None:
    """The trimmed prefix of a partially overlapping segment must land in
    retransmitted_bytes; before round 6 it landed in NO bucket, silently
    violating the every-byte-lands-somewhere invariant. Distinct from the
    full-overlap path: retransmitted_segments must NOT increment here, the
    segment carried new bytes and was (partially) fed.
    """
    req = read_req(tid=1)  # 12 bytes
    c = Conn()
    start = c.seq[c.client]
    c.send(req[:8])  # bytes 0..8 delivered
    c.send(req[4:], seq=start + 4)  # re-covers bytes 4..8 (overlap 4) + new 8..12
    c.recv(read_resp(tid=1))
    result = ingest(tmp_path, c)
    assert result.anomalies == []
    assert len(result.records) == 1  # frame assembled exactly once from the new tail
    assert result.retransmitted_bytes == 4  # the trimmed prefix, byte-exact
    assert result.retransmitted_segments == 0  # not a pure retransmit


def test_sequence_gap_counted_never_spliced(tmp_path: Path) -> None:
    req = read_req(tid=7)
    c = Conn()
    c.send(req[:5])  # partial frame delivered...
    c.send(read_req(tid=8), seq=c.seq[c.client] + 40)  # ...then a 40-byte hole
    c.recv(read_resp(tid=8))
    result = ingest(tmp_path, c)
    kinds = result.anomaly_counts()
    assert kinds.get("reassembly_gap") == 1
    assert kinds.get("truncated_stream") == 1  # pre-gap partial flushed, not spliced
    (rec,) = result.records  # post-gap traffic still parses
    assert rec.start_address == 100


# --- direction attribution (D10) ----------------------------------------------


def test_port_rule_alone_no_handshake(tmp_path: Path) -> None:
    c = Conn(handshake=False)  # mid-capture stream, server on 502
    c.send(read_req(tid=1))
    c.recv(read_resp(tid=1))
    result = ingest(tmp_path, c)
    assert result.anomalies == []
    assert len(result.records) == 1


def test_syn_rule_alone_nonstandard_port(tmp_path: Path) -> None:
    c = Conn(server=(SERVER, 8502))  # handshake present, no 502
    c.send(read_req(tid=1))
    c.recv(read_resp(tid=1))
    result = ingest(tmp_path, c)
    assert result.anomalies == []
    (rec,) = result.records
    assert rec.server_ip == SERVER


def test_no_evidence_is_unattributed_not_guessed(tmp_path: Path) -> None:
    c = Conn(server=(SERVER, 8502), handshake=False)
    c.send(read_req(tid=1))
    c.recv(read_resp(tid=1))
    result = ingest(tmp_path, c)
    assert result.records == []
    (a,) = result.anomalies
    assert a.kind == "unattributed_stream"
    assert "2 payload packets" in a.detail


def test_conflicting_evidence_is_refused(tmp_path: Path) -> None:
    """SYN sent FROM source port 502: port rule and SYN rule disagree."""
    c = Conn(client=(CLIENT, 502), server=(SERVER, 8502))
    c.send(read_req(tid=1))
    c.recv(read_resp(tid=1))
    result = ingest(tmp_path, c)
    assert result.records == []
    (a,) = result.anomalies
    assert a.kind == "direction_conflict"


# --- stream lifecycle (D11) -----------------------------------------------------


def test_new_syn_resets_incarnation(tmp_path: Path) -> None:
    """Stale outstanding TIDs must not bleed across a connection reset."""
    c = Conn()
    c.send(read_req(tid=1))  # unanswered in incarnation 1
    c._pkt(c.client, c.server, flags="S", seq=9999)  # new SYN, same 4-tuple
    c.recv(read_resp(tid=1), seq=7000)  # response arrives in incarnation 2
    result = ingest(tmp_path, c)
    assert result.records == []  # must NOT pair across the reset
    kinds = result.anomaly_counts()
    assert kinds.get("orphan_request") == 1
    assert kinds.get("orphan_response") == 1


# --- determinism & hostile input -----------------------------------------------


def test_deterministic_across_runs(tmp_path: Path) -> None:
    c = Conn()
    c.send(read_req(tid=1) + b"\xff\xff\xff\xff\xff\xff\xff")  # trailing garbage
    c.recv(read_resp(tid=1))
    pkts_path = tmp_path / "det.pcap"
    wrpcap(str(pkts_path), c.pkts)
    r1 = ingest_pcap(str(pkts_path))
    r2 = ingest_pcap(str(pkts_path))
    assert r1.records == r2.records
    assert r1.anomalies == r2.anomalies


@pytest.mark.timeout(5)
def test_garbage_stream_bounded_and_counted(tmp_path: Path) -> None:
    """A non-Modbus stream that passes attribution: counted, never a crash."""
    c = Conn()
    c.send(b"\x01\x02" * 400)
    result = ingest(tmp_path, c)
    assert result.records == []
    assert result.anomalies  # every skipped byte is in a counted anomaly
    assert all(a.stream for a in result.anomalies)


def test_non_tcp_packets_tallied(tmp_path: Path) -> None:
    c = Conn()
    c.send(read_req(tid=1))
    c.recv(read_resp(tid=1))
    arp = Ether() / b"\x00\x01\x08\x00"  # non-IP frame
    arp.time = 999.0
    path = tmp_path / "mixed.pcap"
    wrpcap(str(path), [arp, *c.pkts])
    result = ingest_pcap(str(path))
    assert result.packets_non_tcp == 1
    assert len(result.records) == 1


ETH_TRAILER = b"\x00\x00\x00\x00"


def test_ethernet_trailer_trimmed_to_ip_declared_length(tmp_path: Path) -> None:
    """A frame can carry bytes after the IP datagram (Ethernet padding, or a
    trailer added by the capturing NIC). On read-back scapy keeps them as a
    Padding layer under TCP, so bytes(tcp.payload) is the Modbus request plus
    the trailer. ingest trims the payload to the length the IP header declares.
    Without the trim, the 4 trailer bytes would stay in the client-side stream after the request."""
    c = Conn()
    req = c.send(read_req(tid=1, addr=100, qty=10))
    c.pkts[-1] = padded = Ether(bytes(req) + ETH_TRAILER)
    padded.time = req.time
    c.recv(read_resp(tid=1, qty=10))
    result = ingest(tmp_path, c)
    written = rdpcap(str(tmp_path / "fixture.pcap"))[3]  # after the 3-packet handshake
    assert bytes(written[TCP].payload) == read_req(tid=1, addr=100, qty=10) + ETH_TRAILER
    assert result.anomalies == []
    (rec,) = result.records
    assert (rec.function_code, rec.start_address, rec.quantity) == (3, 100, 10)


# --- D13: FC 08 and FC 43 pair into address-less records ------------------------

FC08_QUERY = b"\x08\x00\x00\xa5\x37"  # sub-function 0x0000 (return query data), echoed back
FC43_REQ = b"\x2b\x0e\x01\x00"  # MEI 0x0E, read code 1, object id 0
FC43_RESP = b"\x2b\x0e\x01\x01\x00\x00\x02" + b"\x00\x05ACME!" + b"\x01\x04V1.0"


def test_fc08_pairs_to_addressless_record(tmp_path: Path) -> None:
    c = Conn()
    c.send(frame(1, 1, FC08_QUERY))
    c.recv(frame(1, 1, FC08_QUERY))
    result = ingest(tmp_path, c)
    assert result.anomalies == []
    (rec,) = result.records
    assert rec.function_code == 8 and rec.subfunction == 0x0000
    assert (rec.start_address, rec.quantity, rec.value) == (None, None, None)
    assert not rec.is_write and not rec.is_exception


def test_fc43_pairs_to_addressless_record(tmp_path: Path) -> None:
    c = Conn()
    c.send(frame(1, 1, FC43_REQ))
    c.recv(frame(1, 1, FC43_RESP))
    result = ingest(tmp_path, c)
    assert result.anomalies == []
    (rec,) = result.records
    assert rec.function_code == 43 and rec.subfunction == 0x0E
    assert (rec.start_address, rec.quantity, rec.value) == (None, None, None)
    assert "ACME" not in repr(rec) and "V1.0" not in repr(rec)  # object values discarded (D13)


def test_fc08_exception_response_pairs(tmp_path: Path) -> None:
    c = Conn()
    c.send(frame(1, 1, FC08_QUERY))
    c.recv(frame(1, 1, b"\x88\x01"))  # illegal function
    result = ingest(tmp_path, c)
    assert result.anomalies == []
    (rec,) = result.records
    assert rec.function_code == 8 and rec.is_exception
    assert rec.exception_code == 1
    assert rec.subfunction == 0x0000  # from the request


def test_fc08_force_listen_only_unanswered_is_orphan(tmp_path: Path) -> None:
    """D13 limit, pinned (D12 unchanged): FC 08 sub-function 0x0004 (force listen
    only) gets no response by specification, so it stays an orphan_request and
    never becomes a record. The orphan_request detail does not carry the function
    code, so this test relies on the capture holding only that one request:
    exactly one orphan_request and zero records can only have come from it."""
    c = Conn()
    c.send(frame(1, 1, b"\x08\x00\x04\x00\x00"))
    result = ingest(tmp_path, c)
    assert result.records == []
    assert result.anomaly_counts() == {"orphan_request": 1}


def test_existing_record_has_no_subfunction(tmp_path: Path) -> None:
    c = Conn()
    c.send(read_req(tid=1))
    c.recv(read_resp(tid=1))
    (rec,) = ingest(tmp_path, c).records
    assert rec.subfunction is None
