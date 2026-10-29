# Gate 1 malformed-input corpus

22 fixtures = **21 reject/partial + 1 accept**. Every fixture is built from
literal bytes by `generate_corpus.py` (synthetic, deterministic, no captured
traffic) and its exact behaviour is pinned by the golden signature in
`../golden_corpus.py` (ordered `(kind, offset)` per anomaly and `(fc, tid)` per
recovered ADU). This file says what each fixture is *meant* to break; the golden
says what it *does*, and `test_corpus.py` asserts the two agree.

Every fixture runs through the **request-side** parser unless it is listed in
`RESPONSE_FIXTURES` in `../golden_support.py`; those are marked
**(response-side)** below. The golden pins kind and offset only, and for
`fc43_object_overrun` those are identical request-side and response-side
(`malformed_pdu` at offset 0), so the golden does not enforce direction.
Direction is enforced by `test_response_fixtures_use_response_parser` in
`../test_corpus.py` and by the detail test in `../test_mbap.py`.

Classified by expected outcome, not by "malformed", because outcome is what the
parser's fail-closed contract is actually about.

## accept-all (positive control)

| Fixture | Output | Exercises |
|---|---|---|
| `pipelined_valid_3` | 3 ADUs, 0 anomalies | Three valid FC3 read requests pipelined in one segment (tid 1/2/3). The control that proves the gate can fail: a reject-everything parser fails here. |

## accept-N-then-resync (valid ADU(s) AND counted anomalies)

| Fixture | Output | Exercises |
|---|---|---|
| `garbage_after_valid_adu` | 1 ADU, then `bad_length` + `truncated_stream` | A valid FC3 ADU parses, then a zero-length MBAP and trailing `0xff`: framing continues past a good frame and counts what follows. |
| `skip_cascade_realigns` | 2x `bad_protocol_id`, then 1 ADU | 14 bytes of `0xff` cost two 7-byte header skips, then framing REALIGNS onto a valid FC3 ADU. Proves cascade recovery; the golden pins realignment at offset 14. |

## reject-all (>= 1 counted anomaly, 0 valid ADU)

Header-level (the length field cannot be trusted, so the parser consumes exactly
7 header bytes and resumes):

| Fixture | Output | Exercises |
|---|---|---|
| `truncated_mbap_header` | `truncated_stream` | 4-byte MBAP (< 7): partial frame flushed at finish, never overread. |
| `length_zero` | `bad_length` + `truncated_stream` | Length field 0 (below the min of 2). |
| `length_over_max` | `bad_length` + `bad_protocol_id` + `truncated_stream` | Length field `0xFFFF` (above max); the skip-7 lands on bytes that read as a bad protocol id. |
| `length_exceeds_buffer` | `truncated_stream` | Length claims 200 bytes with 5 present: the overread bait; the parser waits, never reads past the buffer. |
| `bad_protocol_id` | `bad_protocol_id` + `truncated_stream` | Protocol id `0xDEAD` (not 0): not Modbus TCP. |
| `single_byte` | `truncated_stream` | One byte `0x00`: sub-header partial. |
| `all_ff` | 9x `bad_protocol_id` + `truncated_stream` (10 total) | 64 bytes of `0xff`: a bounded skip-7 cascade at a regular 7-byte stride (offsets 0..56, then 63). **This is one code path exercised ten times over uniform garbage, a bounded-cascade stress case, not ten distinct conditions.** |
| `skip_cascade_misaligned` | 3x `bad_protocol_id` + `truncated_stream` (4 total) | 10 bytes of `0xff`: the second skip-7 lands mid-frame and eats into the following valid ADU, which is NOT recovered. The documented best-effort limit and the negative twin of `skip_cascade_realigns`. |

PDU-level (well-framed ADU, bad PDU costs exactly that one ADU):

| Fixture | Output | Exercises |
|---|---|---|
| `unknown_function_code` | `unknown_function_code` | FC `0x2A` (42), outside the supported set. |
| `fc3_quantity_zero` | `malformed_pdu` | FC3 read, quantity 0 (below the min of 1). |
| `fc3_quantity_absurd` | `malformed_pdu` | FC3 read, quantity `0xFFFF` (above the spec max of 125). |
| `fc16_quantity_absurd` | `malformed_pdu` | FC16 write-multiple, absurd quantity. |
| `fc15_bytecount_mismatch` | `malformed_pdu` | FC15 write-coils, byte count inconsistent with quantity. |
| `fc6_short_data` | `malformed_pdu` | FC6 write-single, PDU truncated to 2 bytes. |
| `exception_bit_on_request` | `unknown_function_code` | Request-side `0x83` (FC3 with the exception bit): must surface as unknown FC, never be laundered to a well-formed FC3 (round-6 guard). |
| `exception_bit_request_padded` | `unknown_function_code` | Same guard with extra intra-frame PDU bytes (`0x99 0x99` inside the framed length): proves a bad-FC ADU consumes its whole framed PDU, not a fixed size. Renamed from `exception_trailing_garbage`; the bytes are intra-frame, not trailing garbage outside a frame (a real outside-the-frame case is a Gate 2 gap in GATES.md). |
| `fc08_short_data` | `malformed_pdu` | FC 08 diagnostics with one data byte: the sub-function needs two (D13). |
| `fc43_other_mei` | `unknown_function_code` | FC 43 with MEI type `0x0D` (CANopen): only MEI `0x0E` is parsed, so this stays unknown, not malformed and not an ADU (D13). |
| `fc43_object_overrun` **(response-side)** | `malformed_pdu` | FC 43 read device id response whose second object declares 9 value bytes but carries 4: the object-list walk must stop at the PDU end. Detail `fc 43 response object list overruns pdu` is pinned in `test_mbap.py` (the golden does not pin detail). |
