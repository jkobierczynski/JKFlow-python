# JKFlow.py — Usage Manual

`JKFlow.py` is a Python port of the Perl `JKFlow.pm` FlowScan reporting module. It
reads NetFlow records (from **nfdump/nfcapd** files), counts traffic per subnet,
direction, protocol, and service according to an XML config, and writes the results
into **RRD** time-series databases (plus optional HTML scoreboards). The RRDs are
then graphed by `JKGrapher.pl`.

---

## 1. What it does, in one picture

```
nfpcapd  ──►  /var/flows/nfdump/nfcapd.YYYYMMDDHHMM
                        │
                        ▼
                   JKFlow.py  ──(reads config)──  JKFlow.xml
                        │
                        ├──►  /var/flows/rrds/…      (RRD time-series)
                        ├──►  /var/flows/reports/…   (HTML scoreboards, if configured)
                        └──►  /var/flows/nfdump/processed/   (consumed files)
```

One flow file = one reporting interval = one RRD update per counter.

---

## 2. Command line

```
JKFlow.py [options] FILE [FILE ...]
```

`FILE` is one or more `nfcapd` files (or nfdump CSV files with `--csv`, or `-` for
stdin). Globs like `/var/flows/nfdump/nfcapd.20*` are expanded by your shell.

### Options

| Option | Default | Description |
|---|---|---|
| `-c`, `--config PATH` | `$JKFLOW_XML` or `/usr/local/bin/JKFlow.xml` | Path to `JKFlow.xml`. |
| `--rrddir DIR` | *(from config)* | Override `<rrddir>` from the config. |
| `--scoredir DIR` | *(from config)* | Override `<scoredir>` from the config. |
| `--nfdump PATH` | `nfdump` | Path to the `nfdump` binary. |
| `--csv` | off | Treat inputs as nfdump **CSV** files (or `-` = stdin) instead of binary `nfcapd`. |
| `--processed-dir DIR` | *(none)* | After processing, move each file here. Relative name → a subdir of the file's own directory; absolute path → all there. The live `nfcapd.current.*` is never moved. |
| `--rrd-start EPOCH\|first` | *(none)* | Anchor the start time of **newly created** RRDs, for back-filling old captures. `first` = one step before the earliest input file. Only affects RRDs that don't yet exist. |
| `--no-sort` | off | Process files in the given order instead of sorting by capture time. |
| `--include-current` | off | Also process the live `nfcapd.current.*` file (skipped by default). |
| `-v`, `--verbose` | off | Log at INFO instead of WARNING. |

### Default behaviour worth knowing

- **Files are sorted by capture time before processing** (from the `nfcapd`
  filename), so RRD updates are always monotonic regardless of shell glob order.
  `--no-sort` turns this off.
- **The live capture file (`nfcapd.current.*`) is skipped** — it's still being
  written. `--include-current` overrides.
- **Config resolution order:** `-c` → `JKFLOW_XML` env var → `/usr/local/bin/JKFlow.xml`.
- **The RRD path comes from `<rrddir>` in the config.** The `--rrddir` flag and the
  `/var/flows/rrds` default in the code are only fallbacks/overrides.

---

## 3. The config file (`JKFlow.xml`)

Minimal working example:

```xml
<config>
  <rrddir>/var/flows/rrds</rrddir>
  <scoredir>/var/flows/reports</scoredir>
  <sampletime>300</sampletime>

  <all localsubnets="10.0.2.0/24">
    <total/>
    <protocols>tcp,udp</protocols>
    <otherprotocols/>
    <services>80/tcp,443/tcp,53/udp</services>
    <otherservices/>
  </all>

  <directions>
    <direction name="dmz" fromsubnets="10.0.2.0/24" tosubnets="0.0.0.0/0">
      <total/>
      <services>22/tcp</services>
    </direction>
  </directions>
</config>
```

### Elements

- **`<rrddir>` / `<scoredir>`** — where RRDs and HTML scoreboards are written.
- **`<sampletime>`** — the RRD step in seconds (default 300 = 5 min). Match your
  nfpcapd rotation interval (`-t`).
- **`<all localsubnets="…">`** — the "everything" view. `localsubnets` defines what
  counts as inside; traffic from inside→outside is `out`, outside→inside is `in`,
  and inside→inside is not counted here.
  - `<total/>` — count total bytes/packets/flows.
  - `<protocols>tcp,udp</protocols>` — per-protocol counters.
  - `<otherprotocols/>` — a catch-all "other" protocol bucket.
  - `<services>80/tcp,443/tcp,53/udp</services>` — per-service counters (by
    destination, then source port). Ranges like `1024-2048/tcp` are allowed.
  - `<otherservices/>` — catch-all "other" service bucket.
- **`<directions><direction name="…" fromsubnets="…" tosubnets="…">`** — a scoped
  view of traffic from one set of subnets to another. `0.0.0.0/0` means "anywhere".
  Directions can contain the same counters (`<total/>`, `<services>`, etc.).

> Directions map naturally to zone/conduit boundaries — e.g. a direction per OT
> segment gives you east-west visibility between zones.

Optional (advanced) elements the engine supports, matching `JKFlow.pm`: `<tos>`,
`<dscp>`, `<multicast>`, `<ftp>`, `<scoreboard>` / `<scoreboardother>` (topN tuple
tables), `<monitor>yes</monitor>`, AS-based directions, and router/interface groups.

> **Scoreboards are opt-in.** `/var/flows/reports` stays empty until a direction
> contains a `<scoreboard>` block. That's expected, not a bug.

---

## 4. Common workflows

### First-time historical back-fill

rrdtool stamps a new RRD's start time at "now" and rejects older data, so seeding
fresh RRDs from old captures needs an anchor:

```bash
# start clean if RRDs were created earlier at "now"
sudo rm -rf /var/flows/rrds/*

/opt/jkflow/venv/bin/python /opt/jkflow/JKFlow.py \
    -c /usr/local/bin/JKFlow.xml \
    --rrd-start first --processed-dir processed \
    /var/flows/nfdump/nfcapd.20*
```

`--rrd-start first` anchors every new RRD one step before your earliest file; you'll
see a single `Anchoring new RRDs at … (…)` line and no `illegal attempt` warnings.

### Steady-state (cron)

Once the RRDs exist, drop `--rrd-start` — live runs append forward in time:

```cron
*/5 * * * * root /opt/jkflow/venv/bin/python /opt/jkflow/JKFlow.py \
    -c /usr/local/bin/JKFlow.xml --processed-dir processed \
    /var/flows/nfdump/nfcapd.20* >> /var/log/jkflow.log 2>&1
```

`--processed-dir processed` moves each consumed file into
`/var/flows/nfdump/processed/`, so the next run only sees new files and never
re-feeds old timestamps.

### Ad-hoc / testing without the daemon

Process a pre-exported CSV or pipe nfdump straight in:

```bash
nfdump -r /var/flows/nfdump/nfcapd.20260813060000 -o csv > /tmp/flows.csv
python3 JKFlow.py -c JKFlow.xml --csv /tmp/flows.csv

# or via stdin
nfdump -r /var/flows/nfdump/nfcapd.20* -o csv | python3 JKFlow.py -c JKFlow.xml --csv -
```

### Inspect what a file contains (sanity check)

```bash
nfdump -r /var/flows/nfdump/nfcapd.20260813060000 -o csv | head
```

If that shows rows with `srcAddr,dstAddr,…`, JKFlow will read it.

---

## 5. Output

For each configured view, JKFlow writes RRDs named by what they measure, under
`<rrddir>/<view>/`:

```
/var/flows/rrds/
├── all/
│   ├── total.rrd
│   ├── protocol_tcp.rrd, protocol_udp.rrd, protocol_other.rrd
│   └── service_tcp_https_dst.rrd, service_udp_domain_src.rrd, …
└── dmz/
    ├── total.rrd
    └── service_tcp_ssh_dst.rrd, …
```

Each RRD has six data sources — `in_bytes, out_bytes, in_pkts, out_pkts,
in_flows, out_flows` — all `ABSOLUTE`, stored at the configured step with the
standard FlowScan RRA set (5-min, 30-min, 2-hour, daily rollups). Values are scaled
by the direction's `samplerate`.

Check the numbers directly with rrdtool:

```bash
rrdtool lastupdate /var/flows/rrds/all/total.rrd
rrdtool fetch /var/flows/rrds/all/total.rrd AVERAGE -s -1h
```

---

## 6. How counting works (brief)

For each flow record JKFlow:

1. Reads `srcaddr, dstaddr, srcport, dstport, protocol, bytes, pkts` (and
   tos/AS/interface when present).
2. For `<all>`, checks `localsubnets` to decide direction: inside→outside = `out`,
   outside→inside = `in`.
3. For each `<direction>`, matches `fromsubnets`/`tosubnets` (via a Patricia trie).
4. Increments the matching `total` / `protocol` / `service` counters.
5. After the whole file, writes one RRD update per counter at the file's capture
   time, then zeroes the counters for the next file.

IPv4 only (as in the Perl original); IPv6 flows are skipped.

---

## 7. Troubleshooting

**`Processed 0 flows`** — the reader saw no usable rows. Confirm the file parses:
`nfdump -r FILE -o csv | head`. The reader accepts both nfdump 1.7 verbose headers
(`srcAddr,…`) and older terse ones (`sa,…`).

**`illegal attempt to update using time X when last update time is Y`:**
- **Y is "now" / far in the future** → you're back-filling old data into fresh
  RRDs. Use `--rrd-start first` (and `rm -rf /var/flows/rrds/*` once).
- **X < Y by a normal interval** → a file was re-processed. Use `--processed-dir`
  so files aren't fed twice, or clear the RRDs.
- **files out of order** → sorting is automatic; only relevant if you passed
  `--no-sort`.

**RRDs appearing at `/all`, `/dmz` (filesystem root)** — fixed in ≥ 0.1.2; update
`JKFlow.py`. Remove the stray `/all`, `/dmz` dirs.

**`ERROR updating …: 'NoneType' object has no attribute 'update'`** — the Python
`rrdtool` binding isn't installed. Install the distro package `python3-rrdtool`
(the deps playbook does this) or run inside the provided venv.

**Nothing in `/var/flows/reports`** — no `<scoreboard>` block in the config. Add
one to a direction if you want topN tables.

**Grapher shows a blank image / "can't open RRD"** — `www-data` can't read the
RRDs, or `JKGrapher.pl` is reading a config with the wrong `<rrddir>`. Run
`sudo chmod -R o+rX /var/flows/rrds` and confirm the path.

---

## 8. Quick reference

```bash
# back-fill history
JKFlow.py -c JKFlow.xml --rrd-start first --processed-dir processed \
          /var/flows/nfdump/nfcapd.20*

# steady-state (cron, every 5 min)
JKFlow.py -c JKFlow.xml --processed-dir processed /var/flows/nfdump/nfcapd.20*

# from CSV / stdin
nfdump -r FILE -o csv | JKFlow.py -c JKFlow.xml --csv -

# override output dirs for a one-off
JKFlow.py -c JKFlow.xml --rrddir /tmp/rrds --scoredir /tmp/reports FILE
```
