# Capture investigation tooling

This repository records both sides of the Growatt TCP connection in PCAPNG
files, validates and decrypts the Growatt frames, and offers several ways to
inspect them. The quickest path is:

1. use the web view to find an unusual key and its time;
2. use `bulk-print` for already-decoded telemetry;
3. use a small scanner when direction, acknowledgements, or genuinely unknown
   keys matter; and
4. compare a nearby `poll/*.json` file with the decoded values.

Run commands in this document from the repository root unless stated
otherwise. Captures and poll dumps contain logger/inverter serial numbers and
possibly other device or account data. Do not paste an unredacted body into an
issue or commit it.

## Vocabulary

### Capture file and capture packet

The proxy creates a file named `<epoch-ms>.<source-port>.pcapng` for each TCP
connection. For example, `1790029855261.49160.pcapng` began at approximately
the time represented by epoch millisecond `1790029855261`; `49160` was the
inverter connection's source port.

Each PCAPNG Enhanced Packet Block contains one TCP read made by the proxy. This
is a *capture packet*, not necessarily one Growatt protocol frame: a read can
contain several complete frames. `decode::read_packets_from` splits such a
block into individual frames.

The proxy writes two PCAPNG interfaces solely to preserve direction:

| Interface | Rust/UI direction | Meaning |
| --- | --- | --- |
| `0` | `FromInverter` / `from_inverter` | logger/inverter to upstream server |
| `1` | `ToInverter` / `to_inverter` | upstream server to logger/inverter |

### Frame, header, body, and key

A Growatt frame starts with this eight-byte header:

```text
u0 seq u2 major len_hi len_lo n0 n1
```

`len_hi:len_lo` gives the transmitted data length following the header. The
reader validates the frame CRC, XOR-decrypts the data with the repeating key
`Growatt`, and removes the two trailing CRC bytes. In Rust, `Packet.body` is
this decrypted body.

The UI's six-hex-digit **key** is `major`, `n0`, and `n1` concatenated. Thus
`major=0x06, n0=0x51, n1=0x04` is shown as `065104`. It is a convenient local
classification, not a cryptographic key.

### UI labels

The labels are observations maintained in `view/src/whole-file.tsx`; they are
not emitted by the inverter and do not affect parsing.

| Key | UI label | Present interpretation |
| --- | --- | --- |
| `065129` | `serials and date` | identification/date exchange |
| `060118` | `single statement chat` | short control exchange |
| `060116` | `all nulls` | mostly/all-zero control exchange |
| `060119` | `boot chat` | startup exchange |
| `065119` | `two bytes at the end` | minimally understood exchange |
| `065104` | `config dump?` | historical, tentative label; inverter-to-server frames contain main inverter telemetry |
| `065120` | `data dump` | meter/grid telemetry |
| anything else | `unknown key` | absent from the UI lookup table, not malformed or necessarily novel |

The UI assigns a label by key alone. It does not take direction or body length
into account, so a large telemetry frame and its one-byte acknowledgement get
the same label. A UI count is therefore a count of key hits, not necessarily a
count of data-bearing records.

## What is available

### Capture producer: `proxy`

```sh
cargo run --bin proxy -- <upstream-host:port>
```

The proxy listens for the inverter/logger on TCP port 5279 and forwards the
connection to the supplied upstream address. For each connection it writes a
root-level PCAPNG file and publishes useful `065104`/`065120` fields to retained
MQTT topics under `inverter/<serial>/<field>`. MQTT connection settings come
from the environment via `mqtt-reeze`. Capturing production traffic changes
the network path and requires valid MQTT configuration; it is not necessary
for offline analysis of existing files.

### Web capture browser: `serve` and `view/`

Start the JSON backend in the repository root:

```sh
cargo run --bin serve
```

In another terminal, start the UI:

```sh
cd view
npm ci
npm run dev
```

The backend listens on port 4444, lists root-level files matching
`<digits>.<digits>.pcapng`, and exposes parsed frames as JSON. The browser shows
a per-key count followed by every frame's direction, time relative to the
first frame, label/key, decoded body length, and a printable body rendering.
It is the best overview, but its counts combine directions.

### Structured telemetry printer: `bulk-print`

```sh
cargo run --quiet --bin bulk-print -- 1790029855261.49160.pcapng
```

It accepts one or more captures, combines their frames, sorts by timestamp,
and prints tab-separated output. For `065104` and `065120`, it uses field
definitions in `src/tables.rs` and emits one row per useful field:

```text
RFC3339 timestamp<TAB>key<TAB>field name<TAB>scaled value
```

For another key it emits one row containing an unambiguous byte rendering:

```text
RFC3339 timestamp<TAB>key<TAB>body
```

Important filters are built into this binary: it only prints
inverter-to-server frames, skips bodies shorter than 60 bytes, reads the two
30-byte serial fields at the start of the body, and currently keeps only
inverter serials beginning with `E`. Consequently it does **not** show
one-byte acknowledgements and is not a complete key counter.

To show the data-bearing side of an already identified key:

```sh
cargo run --quiet --bin bulk-print -- 1790029855261.49160.pcapng \
  | awk -F '\t' '$2 == "065103"'
```

Be aware that this prints the full decoded body for an unknown key and can
expose serial numbers. Also, counting `bulk-print` lines does not count
packets: every recognized telemetry packet produces many field rows.

### Experimental printer: `print`

`src/bin/print.rs` contains useful exploratory grouping, frequency, and bucket
code. Most of it is currently disabled behind `if false`, while the enabled
`065120` path treats byte offsets as 32-bit-array indices. At the time of
writing it panics on the example capture (`len is 42 but index is 72`). Treat
it as a workbench to repair or borrow from, not a ready capture-report command.

### Decoder library

`src/decode.rs` is the authoritative local reader. It:

- reads PCAPNG blocks and maps interfaces to direction;
- splits multiple Growatt frames in one capture block;
- checks declared lengths and CRCs;
- XOR-decrypts bodies; and
- exposes timestamps, headers, keys, serials, and big-endian integer helpers.

Prefer adding a small Rust binary around `read_packets_from` when an analysis
will become recurring or must reject bad CRCs exactly as the application does.
`src/tables.rs` contains the byte offsets, numeric types, and scale divisors
used for known `065104` and `065120` fields.

### PCAP utilities

`capinfos` gives a fast capture-level sanity check:

```sh
capinfos -c -a -e -u -i 1790029855261.49160.pcapng
```

Its displayed dates follow the shell's local timezone. Wireshark and `tshark`
can inspect the PCAPNG container, but these files use the user-defined
`USER12`/`USER13` link types. Without a custom dissector they do not know the
Growatt framing, XOR transformation, or local direction convention; the Rust
decoder or the Python scanner below is usually more useful.

### API poll snapshots

`poll/main.py` calls the official API's `sph_detail` and `sph_energy` methods
about every 110 seconds and writes both responses to a timestamped JSON file.
It requires `GROWATT_API_TOKEN` and `GROWATT_DEVICE_SN`; never commit or print
those environment values.

Inspect a narrow selection rather than dumping the entire response:

```sh
jq '{time: .energy.time,
     status: .energy.status,
     ppv: .energy.ppv,
     pac: .energy.pac,
     vac1: .energy.vac1,
     soc: .energy.soc}' \
  poll/20260922_134950.json
```

The poll filename is generated in the poller's local timezone, capture frame
timestamps are stored and printed by Rust in UTC, and API fields can use the
device/account timezone. Normalize before matching. On 2026-09-22 the
repository's Europe/London clock was BST (UTC+1), so the `13:49:50` poll file
aligns with frames around `12:49:50Z`. In that snapshot, `.energy.time` is
`2026-09-22 13:49:02`; its values match the `065104` frame at
`2026-09-22T12:49:02.598375Z` (for example `ppv=6350`, `pac=6048.8`, and
`soc=100`). Prefer `.energy.time` and telemetry values for this correlation;
fields such as `.detail.lastUpdateTimeText` may reflect a server timezone.

## Isolating unknown keys with Python

The standard-library scanner at `docs/scripts/scan_grsott.py` understands the
specific PCAPNG and Growatt framing written by this repository. It prints
counts split by direction, followed only by frames whose key is absent from
the UI lookup table. It prints a body hash for comparison without exposing the
serial fields at the start of most bodies.

Unlike `src/decode.rs`, this compact investigative script does not validate
CRC and assumes the writer's default microsecond PCAPNG timestamp resolution.
Use the Rust decoder when either property is significant.

Run it with:

```sh
python3 docs/scripts/scan_grsott.py 1790029855261.49160.pcapng
```

To isolate a particular key instead of all unknown keys:

```sh
python3 docs/scripts/scan_grsott.py --key 065103 \
  1790029855261.49160.pcapng
```

The script reports body length and SHA-256 prefix, but deliberately does not
write decoded bodies because they contain device identifiers. Add an explicit
export under `/tmp` when byte-level inspection is needed, and keep extracts
outside the repository unless they have been reviewed and sanitized.

## Worked example: `1790029855261.49160.pcapng`

The scanner finds 2,393 Growatt frames. Relevant counts are:

| Direction | Key | Frames | Interpretation |
| --- | --- | ---: | --- |
| from inverter | `065104` | 441 | main telemetry bodies |
| to inverter | `065104` | 433 | acknowledgements/control replies |
| both | `065104` | 874 | the UI's `config dump?` total |
| from inverter | `065103` | 1 | unknown 829-byte body |
| to inverter | `065103` | 1 | matching one-byte acknowledgement |
| both | `065103` | 2 | the UI's two `unknown key` hits |

The unknown pair is:

```text
capture=25 from_inverter time=2026-09-21T22:31:15.009395+00:00 key=065103 body_len=829
capture=26 to_inverter   time=2026-09-21T22:31:15.028407+00:00 key=065103 body_len=1
```

Their 19 ms spacing and asymmetric sizes strongly suggest a data frame followed
by its acknowledgement. That is an inference, not yet a decoded protocol
meaning. The useful unknown record to inspect is the first one; the second is
still important evidence of the request/acknowledgement pairing.

When investigating future unknowns, record at least the key, direction,
absolute UTC time, decoded length, nearby frames, repetition rate, and whether
the opposite direction immediately acknowledges it. Then correlate fields
against the closest poll snapshot before assigning a permanent UI label or
adding offsets to `src/tables.rs`.
