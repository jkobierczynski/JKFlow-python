# JKFlow.py — Perl→Python port, completion notes

This finishes the `JKFlow.pm` → `JKFlow.py` conversion. The counting engine was
already ~90% ported; what was missing was the **flow-record intake** (the piece
the Grok session never delivered — it hit its output limit, started narrating
"response was truncated…", and pasted that narration into the source at what was
line 587). That narration is removed and the reader is built.

Target capture format: **nfdump / nfcapd** (confirmed), replacing the dead
cflowd/FlowScan binary format the Perl used.

## How to run

```bash
# Point at your config (or set JKFLOW_XML / use the default /usr/local/bin/JKFlow.xml)
python3 JKFlow.py -c /path/to/JKFlow.xml /var/flows/nfcapd.202311142210

# Multiple files (a night's worth):
python3 JKFlow.py -c JKFlow.xml /var/flows/nfcapd.*

# Pre-exported CSV instead of live nfcapd (also how the tests run, no binary needed):
nfdump -r nfcapd.202311142210 -q -o csv > flows.csv
python3 JKFlow.py -c JKFlow.xml --csv flows.csv

# Override output dirs / nfdump location:
python3 JKFlow.py -c JKFlow.xml --rrddir /data/rrd --scoredir /data/score \
        --nfdump /usr/local/bin/nfdump  /var/flows/nfcapd.*
```

Dependencies: `xmltodict`, `pytricia`, `rrdtool` (the C-binding), `tabulate`,
and the `nfdump` binary on PATH. `rrdtool`/`tabulate`/`pytricia` are import-guarded
so the module still loads (and can be unit-tested) if one is absent — RRD writes
are simply skipped, and a pure-Python longest-prefix matcher stands in for pytricia.

## The flow reader (your swap point)

`NfdumpReader` shells out to `nfdump -r <file> -q -o csv` and parses the CSV by
**column name**, so column-order changes between nfdump builds can't silently
corrupt the mapping. It yields one dict per flow with exactly the keys the engine
uses, and the driver mutates `Cflow.flowvars` **in place** per record — the same
contract the Perl Cflow globals had.

If you ever go back to **flow-tools**, replace only `NfdumpReader` with a class
exposing the same two methods (`records(path)` yielding those dicts, and
`filetime_for(path)`); nothing else changes. `CsvFlowReader` already shows the
pattern.

nfdump CSV columns consumed: `sa da sp dp pr ibyt/byt ipkt/pkt stos/tos in out
sas das ra ts te`. IPv4 only (matches the Perl's `inet_aton`/32-bit masks);
IPv6 rows are skipped rather than mis-counted.

## What was fixed (beyond writing the reader)

Crash-on-run bugs:
- `self.config` was read in 7 places but never assigned → now stored in `parse_config`.
- `socket.getprotobynumber()` was called 5× — **it doesn't exist in Python**. Replaced
  with a `getprotobynumber()` helper built from `/etc/protocols` (with a fallback map),
  plus consistent int-normalisation of protocol keys so service lookups actually hit.
- `struct.pack('N', …)` (a Perl pack code) → `'!I'`.
- `count_function_localsubnets_withas` was referenced but commented out → implemented.
- The `pytricia` trie exposed none of the `add_string`/`match_integer`/`match_string`
  methods the code called → wrapped in a `PatriciaTrie` (integer-IPv4 lookups, pure-Python
  fallback).
- `self.mylist['triesubnets']` came from a `defaultdict(dict)` but was `.append()`-ed as a
  list → initialised as a list.
- Counter buckets (`total`/protocol/tos/dscp/multicast) assumed their sub-dicts pre-existed
  → routed through one autovivifying `bump()` helper.
- Report path assumed every protocol/application bucket had been counted → tolerates
  never-seen buckets (e.g. `protocol 'other'`).

Fidelity fixes (matched back to `JKFlow.pm`):
- **XML::Simple compatibility**: `xmltodict` returns lists with `@name` attribute prefixes,
  but the whole port was written against XML::Simple's `KeyAttr=['name','key','id']`
  folding (name-keyed dicts, attributes merged, text under `content`). Added `_xml_simplify()`
  to reproduce that — without it, any config with `<direction>`s never parsed.
- Service / FTP / "other" branch restored to the `.pm`'s `elsif` chain (the port's `if/elif`
  skipped the `other` bucket whenever FTP was configured).
- Scoreboard tuple expressions were emitted as Perl (`$srcaddr`) and could never `eval`;
  now plain Python names evaluated against the flow vars.
- Aggregate scoreboard data (`newaggdata`) now populated on **every** sample, not only when
  `<scoreboard every=…>` is set (matches the Perl loop structure).

## Verified

`test_jkflow.py` and `test_rrd.py` (included) cover: config parse with folding;
`wanted()` counting (in/out split, service classification, direction/trie matching,
internal-traffic exclusion from `all`); nfdump-CSV parsing with the summary block
skipped and protocol names mapped; nfcapd-filename → filetime; and well-formed
RRD create/update payloads (`timestamp:in_bytes:out_bytes:in_pkts:out_pkts:in_flows:out_flows`).

## Notes / possible follow-ups

- **Performance**: `wanted()` runs ~800k×/file. Reading via `nfdump … -o csv` through a pipe
  plus `csv.DictReader` is the bottleneck. If it's too slow, the fast path is nfdump's binary
  reader (`libnffile`) or a compiled reader; the intake is isolated so this won't touch the
  engine. Trie lookups convert int→dotted-string per call — cache if profiling points here.
- Scoreboard "Tuplekey" shows raw 32-bit ints for address fields (as the Perl did). If you
  want dotted-quad display, format address-typed tuple fields in `_score_tuples`.
- IPv6 is out of scope (the Perl was IPv4-only). Records with v6 addresses are skipped.
