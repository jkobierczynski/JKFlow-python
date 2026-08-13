# Changelog

All notable changes to the JKFlow Python port and its deployment tooling.
Format based on [Keep a Changelog](https://keepachangelog.com/); versions follow
[Semantic Versioning](https://semver.org/).

## Summary

`JKFlow.py` is a Python port of the Perl `JKFlow.pm` FlowScan reporting module —
an XML-configurable NetFlow analyzer that counts traffic per subnet / direction /
service and writes RRD time-series plus HTML scoreboards. The port had stalled
with the flow-record intake never finished (an earlier LLM session hit its output
limit mid-file and left its own "response truncated" narration pasted into the
source). This work completes the port, replaces the dead cflowd capture path with
a modern **nfdump / nfcapd** reader, fixes the bugs that prevented it from running,
and adds Ansible automation to install and serve it on Debian and Devuan. It was
then field-tested on Devuan Excalibur (nfdump 1.7.5, Python 3.13) and hardened
against the differences found there.

Components:
- `JKFlow.py` — the reporting engine + flow reader + CLI driver
- `install-jkflow-deps.yml` — Ansible: install runtime dependencies
- `setup-jkgrapher-apache.yml` — Ansible: serve the `JKGrapher.pl` CGI under Apache
- `.yamllint` — lint config shared by the playbooks

---

## [0.1.0] - 2026-08-13

Initial release: the completed JKFlow Python port and its Debian/Devuan
deployment tooling. Field-tested on Devuan Excalibur (nfdump 1.7.5, Python 3.13);
the environment-specific issues found there are resolved under **Fixed** below.

### Added
- **Flow-record intake (the missing piece).** `NfdumpReader` (shells out to
  `nfdump -r <file> -o csv`, parsed by column name), `CsvFlowReader` (pre-exported
  CSV / stdin), `parse_nfdump_csv()`, `process_file()`, and an argparse `main()`
  CLI driver. Per-record state mutates `Cflow.flowvars` in place, matching the Perl
  global contract; IPv4-only, matching `JKFlow.pm`.
- **`PatriciaTrie`** wrapper exposing the Net::Patricia API the port expects
  (`add_string` / `match_integer` / `match_string`), backed by `pytricia` with a
  pure-Python longest-prefix fallback.
- **`_xml_simplify()`** — reproduces XML::Simple's `KeyAttr=['name','key','id']`
  folding, attribute merging, and text-as-`content` so the parser consumes a real
  `JKFlow.xml` (directions/routergroups/sites/definesets keyed by name).
- **Protocol/service helpers** `getprotobynumber()`, `normalize_proto()`,
  `safe_getservbyport()` (Python's `socket` has no `getprotobynumber`).
- **`count_function_localsubnets_withas()`** implemented (was referenced but stubbed).
- **`install-jkflow-deps.yml`** — Ansible playbook to install the runtime
  dependencies (nfdump + Python deps in a dedicated venv) on Debian/Devuan, with a
  distribution guard and idempotent, lint-clean tasks.
- **`setup-jkgrapher-apache.yml`** — Ansible playbook to serve the `JKGrapher.pl`
  CGI grapher under Apache on Debian/Devuan: installs Apache + Perl RRD/CGI bindings
  (`librrds-perl`, `libcgi-pm-perl`), enables `cgid`, deploys the operator's script
  via a scoped `ScriptAlias`, validates config with `apache2ctl configtest`, and
  manages the service through the init-agnostic `service` module (no systemd
  assumption). Defaults to localhost-only access.
- **`.yamllint`** — shared lint config (120-col), aligned with ansible-lint.

### Changed
- Optional imports (`rrdtool`, `xmltodict`, `tabulate`, `pytricia`) are guarded so
  the module imports and unit-tests without every dependency present; RRD writes are
  skipped when `rrdtool` is unavailable.

### Fixed
- `self.config` was read in seven places but never assigned → stored in `parse_config`.
- `socket.getprotobynumber()` (nonexistent in Python) calls → replaced with helper.
- `struct.pack('N', ...)` (a Perl pack code) → `'!I'`.
- `pytricia` objects lacked the `add_string`/`match_integer`/`match_string` methods
  the code called → resolved by the `PatriciaTrie` wrapper.
- `mylist['triesubnets']` came from a `defaultdict(dict)` but was `.append()`-ed as a
  list → initialised as a list.
- Counter buckets (`total`/protocol/tos/dscp/multicast/service) assumed pre-existing
  sub-dicts → routed through one autovivifying `bump()` helper.
- Report path assumed every bucket was counted → tolerates never-seen buckets
  (e.g. `protocol 'other'`).
- Service / FTP / "other" classification restored to `JKFlow.pm`'s `elsif` chain
  (the port's `if/elif` skipped the "other" bucket whenever FTP was configured).
- Scoreboard tuple expressions were emitted as Perl (`$srcaddr`) and could never
  `eval` → rewritten as Python names evaluated against the flow variables.
- Aggregate scoreboard data now populated on every sample, not only when
  `<scoreboard every=…>` is set (matches the Perl loop structure).
- **Flow reader: nfdump 1.7 CSV column names.** nfdump 1.7 emits `-o csv` with
  verbose headers (`firstSeen,proto,srcAddr,srcPort,dstAddr,dstPort,packets,bytes`)
  instead of the older terse ones (`ts,pr,sa,sp,da,dp,ipkt,ibyt`). The reader
  looked only for the terse names, treated their absence as the summary block, and
  returned **0 flows for every file**. Column resolution is now alias-based against
  the actual header, supporting both the 1.7 verbose and legacy terse formats;
  fields absent for locally captured flows (exporter/AS/interface/tos) default to 0.
- **Flow reader: sub-minute nfcapd filenames.** `filetime_for()` only parsed
  12-digit `nfcapd.YYYYMMDDHHMM`. With rotation under 60s, nfcapd appends seconds
  (`nfcapd.YYYYMMDDHHMMSS`, 14 digits); these fell back to file mtime, collided on
  the same second, and produced RRD `illegal attempt to update ... (minimum one
  second step)` errors. Both 12- and 14-digit names are now parsed.
- **`install-jkflow-deps.yml`: rrdtool build failure on Python 3.13.** The pip
  `rrdtool` package (0.1.16) does not compile against Python 3.13's C API. Switched
  to the distribution binding `python3-rrdtool` (apt) and create the virtualenv
  with `--system-site-packages` so it is importable; only `pytricia` still builds
  from source. Added detection that removes a stale venv lacking system
  site-packages so it is rebuilt correctly on re-run.
- **`install-jkflow-deps.yml`: nfdump PATH check.** The check used `command -v`
  under the `command` module, which execs binaries directly and cannot run a shell
  builtin (it errored looking for a program named `command`). Moved to the `shell`
  module (with a scoped `noqa`), which is the correct tool since Debian 13/Excalibur
  deprecated the standalone `which` binary.

### Removed
- The leaked "response was truncated…" narration an earlier LLM session pasted into
  the source (former lines 587–589), which had left `push_directions` visually cut
  and the reader undelivered.

---

## Known limitations / next steps
- IPv6 is out of scope (the Perl original is IPv4-only); IPv6 flows are skipped.
- `wanted()` runs ~800k×/file; the `nfdump … -o csv` pipe + `csv.DictReader` is the
  likely bottleneck. The intake is isolated, so a faster reader can be swapped in
  without touching the engine.
- No init script yet for running `nfpcapd` (and optionally JKFlow) as a boot service
  on Devuan (sysvinit/OpenRC) — candidate for a future release.

---

## Appendix: suggested commit grouping

If committing this as discrete changes rather than one squash, a clean sequence:

```
chore: remove leaked LLM narration from JKFlow.py source
fix(config): store parsed config on self; add XML::Simple KeyAttr compatibility
fix(proto): add getprotobynumber/normalize_proto/safe_getservbyport helpers
fix(trie): wrap pytricia with Net::Patricia-style PatriciaTrie
fix(counting): implement count_function_localsubnets_withas; autoviv via bump()
fix(counting): restore service/ftp/other elsif chain; scoreboard tuples as Python
feat(reader): add nfdump/CSV flow reader, process_file and main() CLI
chore(imports): guard optional deps (rrdtool/xmltodict/tabulate/pytricia)
feat(ansible): install-jkflow-deps.yml + .yamllint (Debian/Devuan)
fix(ansible): install rrdtool via python3-rrdtool; venv --system-site-packages
fix(ansible): nfdump PATH check via shell (command -v is a builtin)
feat(ansible): setup-jkgrapher-apache.yml (CGI grapher, init-agnostic)
fix(reader): resolve nfdump 1.7 verbose CSV columns via aliases
fix(reader): parse 14-digit sub-minute nfcapd filenames for filetime
```

---

[0.1.0]: https://github.com/USER/REPO/releases/tag/v0.1.0
