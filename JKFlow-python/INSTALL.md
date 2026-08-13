# JKFlow / JKGrapher — Installation Guide

Install and wire up the JKFlow NetFlow pipeline on **Debian 13 (Trixie)** or
**Devuan Excalibur** using the provided Ansible playbooks:

- **`install-jkflow-deps.yml`** — installs nfdump + the Python runtime for `JKFlow.py`
- **`setup-jkgrapher-apache.yml`** — serves the `JKGrapher.pl` CGI grapher under Apache

Both playbooks are init-agnostic (no systemd assumption), so they work on Devuan's
sysvinit/OpenRC as well as on Debian.

> Files referenced: `JKFlow.py`, `JKFlow.sample.xml`, `JKGrapher.pl` (your copy),
> `install-jkflow-deps.yml`, `setup-jkgrapher-apache.yml`, `.yamllint`.

---

## 0. Directory layout

Everything lives under `/var/flows` (the defaults baked into the files):

```
/var/flows/
├── nfdump/            # raw nfcapd flow files written by nfpcapd
│   └── processed/     # files JKFlow has already consumed
├── rrds/              # RRD databases   (<rrddir>  in JKFlow.xml)
└── reports/           # HTML scoreboards (<scoredir> in JKFlow.xml)
```

`JKFlow.py` creates `rrds/` and `reports/` itself on first run; you create
`nfdump/` for the capture daemon.

---

## 1. Install Ansible (on the box you run the playbooks from)

On Devuan/Debian, Ansible installs like any Debian package — it's pure Python, so
the init system is irrelevant to it.

```bash
sudo apt update
sudo apt install ansible          # distro build; fine for these playbooks
```

For a newer release, use pipx instead (PEP 668-safe, no `--break-system-packages`):

```bash
sudo apt install pipx
pipx ensurepath
pipx install --include-deps ansible
```

Verify:

```bash
ansible --version
```

If you plan to run the playbooks against the same machine, no SSH setup is needed —
use a local connection (shown below with `-i "localhost," -c local`).

---

## 2. Install the JKFlow runtime dependencies

`install-jkflow-deps.yml` installs (via apt): `build-essential`, `python3`,
`python3-dev`, `python3-venv`, `python3-pip`, `python3-rrdtool`, `rrdtool`, `nfdump`.
It then creates a virtualenv at `/opt/jkflow/venv` (with `--system-site-packages`
so it can import the distro `python3-rrdtool`) and pip-installs `xmltodict`,
`tabulate`, and `pytricia` into it.

> **Why the venv uses system site-packages:** the pip `rrdtool` package does not
> compile against Python 3.13. We use the distribution's `python3-rrdtool` binding
> instead, and the venv is created so it can see it. Only `pytricia` is built from
> source (needs `build-essential` + `python3-dev`).

Run it (local machine), also deploying `JKFlow.py` to `/opt/jkflow`:

```bash
ansible-playbook -i "localhost," -c local install-jkflow-deps.yml \
    -e jkflow_src=./JKFlow.py
```

Against remote hosts:

```bash
ansible-playbook -i inventory install-jkflow-deps.yml -e jkflow_src=./JKFlow.py
```

The `verify` block at the end confirms `nfdump` is on `PATH` and that all four
Python dependencies import inside the venv.

### Key variables (override with `-e`)

| Variable | Default | Purpose |
|---|---|---|
| `jkflow_target` | `localhost` | Inventory host pattern for the play |
| `jkflow_home` | `/opt/jkflow` | Install directory |
| `jkflow_venv` | `/opt/jkflow/venv` | Virtualenv location |
| `jkflow_src` | *(empty)* | Path on the controller to `JKFlow.py`; empty = deps only |
| `jkflow_apt_packages` | *(see above)* | System packages |
| `jkflow_pip_packages` | `xmltodict, tabulate, pytricia` | venv packages (pin versions here) |

Tags: `packages`, `venv`, `verify` (e.g. `--tags verify`).

If a previous run left a venv **without** system site-packages, the playbook
detects it (reads `pyvenv.cfg`) and rebuilds it correctly — no manual cleanup.

---

## 3. Install the flow config

`JKFlow.py` reads a config file (`JKFlow.xml`) for the subnets, directions,
services, RRD path, etc. A starting point is provided as `JKFlow.sample.xml`:

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

Edit `localsubnets`, the directions, and the services to match your network, then
place it where JKFlow will find it. `JKFlow.py` looks for the config in this order:

1. `-c /path/to/JKFlow.xml` on the command line
2. the `JKFLOW_XML` environment variable
3. `/usr/local/bin/JKFlow.xml` (default)

```bash
sudo cp JKFlow.sample.xml /usr/local/bin/JKFlow.xml   # or keep it project-local
```

> `<rrddir>` in this file is the **authoritative** RRD path. The defaults compiled
> into `JKFlow.py` (`/var/flows/rrds`, `/var/flows/reports`) are only used if the
> config omits `<rrddir>`/`<scoredir>`.

---

## 4. Set up flow capture (nfpcapd)

`nfdump` (with `nfpcapd`) was installed in step 2. Create the flow directory and
start the pcap-to-netflow daemon on your interface:

```bash
sudo mkdir -p /var/flows/nfdump
sudo nfpcapd -i eth0 -l /var/flows/nfdump -I any -t 300 -P /run/nfpcapd.pid -D
```

- `-i eth0` — capture interface (use a SPAN/mirror port or tap for network-wide view)
- `-l /var/flows/nfdump` — output directory (flat; no `-S`)
- `-t 300` — 5-minute rotation, matching `<sampletime>`
- `-D` — daemonize

> **nfpcapd vs nfcapd:** `nfpcapd` builds flows from packets it sniffs on an
> interface. `nfcapd` is the *collector* that receives NetFlow exported by a
> router/switch over UDP. Use `nfpcapd` for local capture; `nfcapd` if a device
> exports flows to this host.

> **nfdump 1.7 note:** compression is `-z=lz4` / `-z=zstd` (there is no `-j`), and
> the verbose printing flag differs by build. Run `nfpcapd -h` for your binary's
> exact options.

Confirm files are being written and are readable:

```bash
ls -l /var/flows/nfdump
nfdump -r /var/flows/nfdump/nfcapd.20* -o csv | head
```

---

## 5. Run JKFlow against captured flows

First, a historical back-fill of everything captured so far (see the JKFlow manual
for the flag details):

```bash
/opt/jkflow/venv/bin/python /opt/jkflow/JKFlow.py \
    -c /usr/local/bin/JKFlow.xml \
    --rrd-start first --processed-dir processed \
    /var/flows/nfdump/nfcapd.20*
```

Then, going forward, a periodic run (cron, every 5 minutes) that picks up new files:

```cron
*/5 * * * * root /opt/jkflow/venv/bin/python /opt/jkflow/JKFlow.py \
    -c /usr/local/bin/JKFlow.xml --processed-dir processed \
    /var/flows/nfdump/nfcapd.20* >> /var/log/jkflow.log 2>&1
```

(Drop `--rrd-start` for the steady-state run — it's only for seeding fresh RRDs
with old data.) After this you should have RRDs under `/var/flows/rrds/all/…` and,
per direction, `/var/flows/rrds/dmz/…`.

---

## 6. Install the JKGrapher CGI under Apache

`setup-jkgrapher-apache.yml` installs Apache + the Perl bindings the grapher needs
(`librrds-perl`, `libcgi-pm-perl`, `libxml-simple-perl`), enables the `cgid`
module, deploys **your** `JKGrapher.pl` under a scoped `ScriptAlias`, validates the
config, and starts Apache through the init-agnostic `service` module.

```bash
ansible-playbook -i "localhost," -c local setup-jkgrapher-apache.yml \
    -e jkgrapher_src=./JKGrapher.pl
```

The grapher is then served at:

```
http://<host>/jkgrapher/JKGrapher.pl
```

Open that base URL to get the grapher's selection form, pick a subnet tree
(`/all`, `/dmz`, …), and it generates the graphs. (The graph image is streamed on
the same request — there is no separate `.png` file.)

### Key variables (override with `-e`)

| Variable | Default | Purpose |
|---|---|---|
| `jkgrapher_target` | `localhost` | Inventory host pattern |
| `jkgrapher_src` | *(empty)* | Path on the controller to `JKGrapher.pl`; empty = set up Apache only |
| `jkgrapher_cgi_dir` | `/usr/lib/cgi-bin/jkgrapher` | Where the script is deployed |
| `jkgrapher_url_path` | `/jkgrapher` | URL prefix (`ScriptAlias`) |
| `jkgrapher_rrddir` | `/var/flows/rrds` | RRD tree the grapher reads |
| `jkgrapher_require` | `Require ip 127.0.0.1 ::1` | Apache 2.4 access control — **localhost only by default** |
| `jkgrapher_fix_rrd_perms` | `false` | If true, `chmod o+rX` the RRD tree so www-data can read it |

Tags: `packages`, `apache`, `deploy`, `verify`.

### Two things the grapher needs to actually draw

1. **It reads the RRD path from `JKFlow.xml`, not from Apache.** `JKGrapher.pl`
   uses `XML::Simple` to parse the config and learn `<rrddir>`. Make sure the
   `JKFlow.xml` the script loads points at `/var/flows/rrds`. (The playbook also
   sets `SetEnv JKFLOW_RRDDIR`, but only scripts that read that env var use it.)
2. **`www-data` must be able to read the RRDs.** Either set
   `-e jkgrapher_fix_rrd_perms=true`, or manually:
   ```bash
   sudo chmod -R o+rX /var/flows/rrds
   ```

### Security note

A CGI grapher that reads your flow RRDs is a live attack surface, so access
defaults to localhost only. Widen it deliberately, e.g. for a management subnet:

```bash
ansible-playbook -i inventory setup-jkgrapher-apache.yml \
    -e jkgrapher_src=./JKGrapher.pl \
    -e 'jkgrapher_require=Require ip 127.0.0.1 ::1 10.0.0.0/24'
```

---

## 7. Verify the whole chain

```bash
# capture is producing files
ls -l /var/flows/nfdump

# JKFlow produced RRDs
ls -R /var/flows/rrds/all | head

# the CGI runs and returns output (HTML form or a PNG)
sudo -u www-data perl /usr/lib/cgi-bin/jkgrapher/JKGrapher.pl | head -c 200; echo

# Apache is up
apache2ctl -t && echo "apache config OK"
```

Then browse to `http://<host>/jkgrapher/JKGrapher.pl`.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `rrdtool` pip build fails on install | pip `rrdtool` won't compile on Python 3.13 | Already handled — the playbook uses apt `python3-rrdtool` + a system-site-packages venv. Don't add `rrdtool` to `jkflow_pip_packages`. |
| nfdump PATH check errors on `command` | `command` is a shell builtin | Already handled — the check uses the `shell` module. |
| `Can't locate XML/Simple.pm` (500 error) | Missing Perl module | `sudo apt install libxml-simple-perl` (now in the playbook). |
| Browser: "image contains errors" | The grapher returned its HTML selection form, not a PNG | Use the base URL and pick a subnet; the request needs the `subdir` parameter the form supplies. |
| RRD files created at `/all`, `/dmz` (root) | Fixed in JKFlow.py ≥ 0.1.2 | Update `JKFlow.py`; remove stray `/all`, `/dmz`. |
| `illegal attempt to update using time …` | Out-of-order files, re-processing, or back-filling into fresh RRDs | See the JKFlow manual: sorting is automatic; use `--processed-dir` and, for back-fills, `--rrd-start first`. |
| Blank graph / "can't open RRD" | www-data can't read RRDs, or wrong path in JKFlow.xml | `chmod o+rX /var/flows/rrds`; check `<rrddir>`. |

For playbook development, `.yamllint` (120-col, aligned with ansible-lint) is
included; both playbooks pass `ansible-lint` at the production profile.
