#!/usr/bin/python3

# JKFlow.py
# A flexible, scalable reporting module for FlowScan, translated from JKFlow.pm
# Original author: Jurgen Kobierczynski <jurgen.kobierczynski@pandora.be>

import socket
import os
import math
import time
import re
import subprocess
from typing import Dict, List, Any, Optional, Iterator
import logging
import ipaddress
import datetime
import struct
from collections import defaultdict

# ---- Optional third-party deps (guarded so the module always imports) --------
try:
    import xmltodict
except ImportError:
    xmltodict = None

try:
    import rrdtool
except ImportError:
    rrdtool = None
    logging.warning("python-rrdtool not available; RRD writes will be skipped")

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None

try:
    import pytricia
except ImportError:
    pytricia = None
    logging.warning("pytricia not available; using pure-python longest-prefix matching")


# ---- Protocol/service helpers (fixes: socket has no getprotobynumber) --------
_PROTO_NUM_TO_NAME: Dict[int, str] = {}


def getprotobynumber(num: int) -> Optional[str]:
    """Reverse of socket.getprotobyname(). Python's socket has no such call,
    so we build the map from /etc/protocols once (with a hard-coded fallback)."""
    global _PROTO_NUM_TO_NAME
    if not _PROTO_NUM_TO_NAME:
        try:
            with open('/etc/protocols') as fh:
                for line in fh:
                    parts = line.split('#', 1)[0].split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        _PROTO_NUM_TO_NAME.setdefault(int(parts[1]), parts[0])
        except OSError:
            pass
        # Ensure the common ones exist even without /etc/protocols
        _PROTO_NUM_TO_NAME.setdefault(1, 'icmp')
        _PROTO_NUM_TO_NAME.setdefault(2, 'igmp')
        _PROTO_NUM_TO_NAME.setdefault(6, 'tcp')
        _PROTO_NUM_TO_NAME.setdefault(17, 'udp')
        _PROTO_NUM_TO_NAME.setdefault(47, 'gre')
        _PROTO_NUM_TO_NAME.setdefault(50, 'esp')
        _PROTO_NUM_TO_NAME.setdefault(51, 'ah')
        _PROTO_NUM_TO_NAME.setdefault(58, 'ipv6-icmp')
    try:
        return _PROTO_NUM_TO_NAME.get(int(num))
    except (TypeError, ValueError):
        return None


def normalize_proto(proto) -> int:
    """Return a protocol as an int, accepting either a numeric string/int or a name."""
    if isinstance(proto, int):
        return proto
    proto = str(proto).strip()
    if proto.isdigit():
        return int(proto)
    return socket.getprotobyname(proto)


def safe_getservbyport(port: int, proto_num: int) -> Optional[str]:
    """getservbyport needs a proto *name* ('tcp'/'udp'); tolerate anything else."""
    name = getprotobynumber(proto_num)
    if name not in ('tcp', 'udp'):
        return None
    try:
        return socket.getservbyport(int(port), name)
    except OSError:
        return None


# ---- Patricia trie wrapper --------------------------------------------------
# The original code called Net::Patricia-style methods (add_string / match_integer
# / match_string). Neither pytricia nor a bare dict provides those, so we wrap.
class PatriciaTrie:
    """Longest-prefix-match trie exposing the Net::Patricia API the port expects.

    IPv4 only, matching JKFlow.pm (inet_aton, 32-bit masks). Keys are stored as
    'a.b.c.d/len' strings; lookups accept an integer IPv4 address (as the Perl
    Cflow layer produced) and return the payload stored with the covering prefix.
    """

    __slots__ = ('_pyt', '_fallback')

    def __init__(self):
        self._pyt = pytricia.PyTricia(32) if pytricia is not None else None
        self._fallback: Dict[Any, Any] = {}  # ip_network -> payload

    @staticmethod
    def _norm(subnet: str) -> str:
        subnet = subnet.strip()
        return subnet if '/' in subnet else subnet + '/32'

    @staticmethod
    def _ip_str(ip) -> str:
        if isinstance(ip, int):
            return str(ipaddress.IPv4Address(ip))
        return str(ip)

    def add_string(self, subnet: str, payload: Any = True) -> None:
        key = self._norm(subnet)
        if self._pyt is not None:
            self._pyt[key] = payload
        else:
            self._fallback[ipaddress.ip_network(key, strict=False)] = payload

    def match_integer(self, ip) -> Optional[Any]:
        """Longest-prefix match for an integer (or string) IPv4 address."""
        if self._pyt is not None:
            try:
                return self._pyt[self._ip_str(ip)]
            except KeyError:
                return None
        addr = ipaddress.ip_address(ip if not isinstance(ip, int)
                                    else ipaddress.IPv4Address(ip))
        best, best_len = None, -1
        for net, payload in self._fallback.items():
            if addr in net and net.prefixlen > best_len:
                best, best_len = payload, net.prefixlen
        return best

    def match_string(self, subnet: str) -> Optional[Any]:
        """Longest-prefix match for a subnet string (used while building the trie)."""
        key = self._norm(subnet)
        if self._pyt is not None:
            try:
                return self._pyt[key]
            except KeyError:
                return None
        return self._fallback.get(ipaddress.ip_network(key, strict=False))

def _xml_simplify(obj, key_attrs=('name', 'key', 'id')):
    """Convert xmltodict output into the shape JKFlow.pm expected from XML::Simple.

    XML::Simple (as JKFlow.pm used it) does three things xmltodict does not:
      * merges attributes into the element's own key namespace (no '@' prefix),
      * stores mixed element text under a 'content' key,
      * folds a list of like-named child elements that each carry a name/key/id
        attribute into a dict keyed by that attribute's value (KeyAttr), removing
        the key attribute from each child.

    Replicating this lets the rest of the port (which indexes directions,
    routergroups, sites, definesets, applications by name) run unchanged against
    a real JKFlow.xml.
    """
    if isinstance(obj, list):
        return [_xml_simplify(x, key_attrs) for x in obj]
    if not isinstance(obj, dict):
        return obj

    out = {}
    for k, v in obj.items():
        if k.startswith('@'):
            out[k[1:]] = v
        elif k == '#text':
            out['content'] = v
        else:
            out[k] = _xml_simplify(v, key_attrs)

    # KeyAttr folding: list-of-dicts where every item carries a key attribute.
    for k, v in list(out.items()):
        if isinstance(v, list) and v and all(isinstance(i, dict) for i in v):
            fold_attr = next((ka for ka in key_attrs if all(ka in i for i in v)), None)
            if fold_attr:
                folded = {}
                for item in v:
                    name = item.pop(fold_attr)
                    folded[name] = item
                out[k] = folded
    return out


# Per-record flow variables.
#
# In JKFlow.pm these were Cflow package globals ($srcaddr, $dstaddr, ...) that
# the FlowScan/Cflow layer set from each binary flow record before calling
# wanted(). Here we keep the exact same contract: a single dict that the flow
# reader mutates IN PLACE for every record, so all the counting closures can
# read Cflow.flowvars['...'] with no per-record allocation. Addresses are
# 32-bit integers (IPv4), matching the Perl.
class Cflow:
    flowvars: Dict[str, int] = {
        'srcaddr': 0, 'dstaddr': 0, 'srcport': 0, 'dstport': 0,
        'protocol': 0, 'bytes': 0, 'pkts': 0, 'tos': 0,
        'exporterip': 0, 'input_if': 0, 'output_if': 0,
        'src_as': 0, 'dst_as': 0, 'endtime': 0,
    }

# Mock FlowScan base class
class FlowScan:
    def createGeneralRRD(self, file: str, fields: List[str]) -> None:
        logging.info(f"Creating RRD file: {file} with fields: {fields}")
        if rrdtool is None:
            return
        step = getattr(self, 'SAMPLETIME', 300)
        fields_config = []
        for i in range(0, len(fields), 2):
            ds_type, ds_name = fields[i:i+2]
            fields_config.append(f"DS:{ds_name}:{ds_type}:600:U:U")
        os.makedirs(os.path.dirname(file), exist_ok=True)
        args = [file, "--step", str(step)]
        # When back-filling historical captures, anchor the RRD's start before the
        # first data point; otherwise rrdtool defaults --start to "now" and rejects
        # any update older than creation time.
        rrd_start = getattr(self, 'rrd_start', None)
        if rrd_start is not None:
            args += ["--start", str(int(rrd_start))]
        args += fields_config + [
            "RRA:AVERAGE:0.5:1:600",
            "RRA:AVERAGE:0.5:6:700",
            "RRA:AVERAGE:0.5:24:775",
            "RRA:AVERAGE:0.5:288:797",
        ]
        rrdtool.create(*args)

    def updateRRD(self, dir: str, name: str, values: List[float]) -> None:
        if rrdtool is None:
            return
        file = os.path.join(getattr(self, 'RRDDIR', '.'), dir.lstrip('/'), name)
        timestamp = getattr(self, 'filetime', int(datetime.datetime.now().timestamp()))
        try:
            rrdtool.update(file, f"{timestamp}:{':'.join(map(str, values))}")
        except Exception as e:
            logging.warning(f"ERROR updating {file}: {e}")

    def perfile(self, *args):
        # Reset per-file totals (parent hook).
        self.totals = {}

# Main JKFlow class
class JKFlow(FlowScan):
    VERSION = "1.053"  # Derived from Perl's $Revision: 1.53 $
    SAMPLETIME = 300
    SCOREKEEP = 10
    AGGSCOREKEEP = 20
    NUMKEEP = 50
    MCAST_NET = int(ipaddress.IPv4Address('224.0.0.0'))
    MCAST_MASK = int(ipaddress.IPv4Address('240.0.0.0'))
    directionroutersgroupsonly = False
    servicescounted = False
    multicast = False
    totals = {}

    ROUTERS = {}
    SERVICES = {}
    mylist = defaultdict(dict)
    RRDDIR = '/var/flows/rrds'
    SCOREDIR = '/var/flows/reports'
    SUBNETS = None
    trie = None

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.filetime = int(time.time())
        self.rrd_start = None            # optional --start for new RRDs (back-fill)
        # Instance-level copies so multiple instances don't share class dicts.
        self.mylist = defaultdict(dict)
        self.mylist['triesubnets'] = []   # this one is a list, not a dict
        self.totals = {}
        self.SUBNETS = self._create_trie()
        self.trie = self._create_trie()
        self.parse_config()

    def _create_trie(self):
        return PatriciaTrie()

    def parse_config(self):
        if xmltodict is None:
            raise RuntimeError("xmltodict is required to parse JKFlow.xml (pip install xmltodict)")
        config_path = getattr(self, 'config_path', None) or os.environ.get(
            'JKFLOW_XML', '/usr/local/bin/JKFlow.xml')
        try:
            with open(config_path, 'r') as f:
                config = xmltodict.parse(f.read(), force_list=(
                    'router', 'routergroup', 'interface', 'subnet', 'site', 'network',
                    'direction', 'application', 'defineset', 'set', 'report', 'tuple'
                ))
        except Exception as e:
            raise RuntimeError(f"Failed to parse {config_path}: {e}")

        # xmltodict != XML::Simple. Fold attributes/text/KeyAttr so the parser
        # below sees the same structure JKFlow.pm did.
        config = _xml_simplify(config)

        # XML::Simple returned the root element's *contents*; strip the wrapper.
        if len(config) == 1:
            (root_key,) = config.keys()
            if isinstance(config[root_key], dict):
                config = config[root_key]

        # CRITICAL: the port reads self.config in parse_direction / push_directions
        # (sites, definesets, routergroups). It was never stored -> AttributeError.
        self.config = config

        self.RRDDIR = config.get('rrddir', '/var/flows/rrds')
        self.SCOREDIR = config.get('scoredir', '/var/flows/reports')
        self.SAMPLETIME = int(config.get('sampletime', self.SAMPLETIME))

        if 'all' in config:
            print("DIRECTION: All")
            all_config = config['all']
            self.mylist['all']['samplerate'] = float(all_config.get('samplerate', 1))
            if 'localsubnets' in all_config:
                self.mylist['all']['localsubnets'] = self._create_trie()
                for subnet in all_config['localsubnets'].split(','):
                    print(f"All: + localsubnets subnet {subnet}")
                    self.mylist['all']['localsubnets'].add_string(subnet)
            self.parse_direction(all_config, self.mylist['all'])
            self.generate_count_packets(self.mylist['all'])

        if 'routergroups' in config and 'routergroup' in config['routergroups']:
            for rg_name, rg_data in config['routergroups']['routergroup'].items():
                print(f"Routergroup: {rg_name}")
                for exporter in rg_data.get('router', []):
                    exp_ip = exporter['exporter']
                    print(f"Exporter: {exp_ip}, ", end="")
                    for key in ['interfaces', 'interfaces_in', 'interfaces_out']:
                        if key in exporter:
                            print(f"{key}: ", end="")
                            for iface in exporter[key].split(','):
                                print(f"interface {iface},", end="")
                                list_ref = self.mylist['routers']['router'].setdefault(exp_ip, {}).setdefault(iface, {}).setdefault('routergroups', [])
                                list_ref.append(rg_name)
                    for key in ['interface', 'interface_in', 'interface_out']:
                        if key in exporter:
                            print(f"{key}: {exporter[key]}", end="")
                            list_ref = self.mylist['routers']['router'].setdefault(exp_ip, {}).setdefault(exporter[key], {}).setdefault('routergroups', [])
                            list_ref.append(rg_name)
                    if 'localsubnets' in exporter:
                        print(f"localsubnets: {exporter['localsubnets']}")
                        list_ref = self.mylist['routers']['router'].setdefault(exp_ip, {}).setdefault('routergroups', [])
                        list_ref.append(rg_name)
                        self.mylist['routers']['router'][exp_ip]['localsubnets'] = self._create_trie()
                        for subnet in exporter['localsubnets'].split(','):
                            self.mylist['routers']['router'][exp_ip]['localsubnets'].add_string(subnet)
                    print()

        self.push_directions(config.get('directions', {}).get('direction', {}), self.mylist['direction'])
        self.push_directions3(self.mylist.get('triesubnets', []), self.trie)
        self.create_wanted()

    def parse_direction(self, refxml: Dict, ref: Dict):
        if 'set' in refxml:
            for set_name in refxml['set']:
                print(f"parseSet: {set_name}")
                self.parse_direction(self.config['definesets']['defineset'][set_name], ref)

        self.push_services(refxml.get('services', ''), ref)
        if 'otherservices' in refxml:
            ref.setdefault('application', {})['other'] = {}

        self.push_protocols(refxml.get('protocols', ''), ref)
        if 'otherprotocols' in refxml:
            ref.setdefault('protocol', {})['other'] = {}

        if 'direction' in refxml:
            ref.setdefault('direction', {})
            self.push_directions(refxml['direction'], ref['direction'])

        if 'application' in refxml:
            ref.setdefault('application', {})
            self.push_applications(refxml['application'], ref)

        for key in ['ftp', 'multicast']:
            if key in refxml and key not in ref:
                ref[key] = {}

        for key in ['tos', 'dscp']:
            if key in refxml and key not in ref:
                ref[key] = {'BE': {}, 'other': {}}

        if 'total' in refxml and 'total' not in ref:
            ref['total'] = {}

        if refxml.get('monitor') == 'yes' and 'monitor' not in ref:
            ref['monitor'] = 'yes'

        if 'scoreboard' in refxml:
            scoreboard = refxml['scoreboard']
            if 'every' in scoreboard:
                ref.setdefault('scoreboard', {}).setdefault('every', {})
                if 'latest' in scoreboard:
                    ref['scoreboard']['latest'] = scoreboard['latest']
                    print(f"Scorepage is {ref['scoreboard']['latest']}")
            if 'tuples' in scoreboard:
                ref.setdefault('scoreboard', {}).setdefault('scorekeep', scoreboard['tuples'].get('scorekeep', self.SCOREKEEP))
                ref['scoreboard'].setdefault('tuples', {})
                for tuple in scoreboard['tuples'].get('tuple', []):
                    tuplestring = '[' + ','.join(p.strip() for p in tuple.split(',')) + ']'
                    ref['scoreboard']['tuples'][tuplestring] = {}
            if 'report' in scoreboard:
                ref.setdefault('scoreboard', {}).setdefault('aggregate', {}).setdefault('report', [])
                for report in scoreboard['report']:
                    if 'base' in report:
                        ref['scoreboard']['aggregate']['report'].append({
                            'count': report['count'],
                            'offset': report.get('offset', 0),
                            'filenamebase': report['base'],
                            'scorekeep': report.get('scorekeep', self.AGGSCOREKEEP),
                            'numkeep': report.get('numkeep', self.NUMKEEP)
                        })

        if 'scoreboardother' in refxml:
            scoreboardother = refxml['scoreboardother']
            if 'every' in scoreboardother:
                ref.setdefault('scoreboardother', {}).setdefault('every', {})
                if 'latest' in scoreboardother:
                    ref['scoreboardother']['latest'] = scoreboardother['latest']
                    print(f"Scorepage is {ref['scoreboardother']['latest']}")
            if 'tuples' in scoreboardother:
                ref.setdefault('scoreboardother', {}).setdefault('scorekeep', scoreboardother['tuples'].get('scorekeep', self.SCOREKEEP))
                ref['scoreboardother'].setdefault('tuples', {})
                for tuple in scoreboardother['tuples'].get('tuple', []):
                    tuplestring = '[' + ','.join(p.strip() for p in tuple.split(',')) + ']'
                    ref['scoreboardother']['tuples'][tuplestring] = {}
            if 'report' in scoreboardother:
                ref.setdefault('scoreboardother', {}).setdefault('aggregate', {}).setdefault('report', [])
                for report in scoreboardother['report']:
                    if 'base' in report:
                        ref['scoreboardother']['aggregate']['report'].append({
                            'count': report['count'],
                            'filenamebase': report['base'],
                            'scorekeep': report.get('scorekeep', self.AGGSCOREKEEP),
                            'numkeep': report.get('numkeep', self.NUMKEEP)
                        })

    def push_protocols(self, refxml: str, ref: Dict):
        if not refxml:
            return
        for proto in refxml.split(','):
            proto = proto.strip()
            if not proto:
                continue
            try:
                proto_num = normalize_proto(proto)
            except OSError:
                raise ValueError(f"Unknown protocol {proto}")
            ref.setdefault('protocol', {})[proto_num] = {}

    def push_services(self, refxml: str, ref: Dict):
        if not refxml:
            return
        for current in refxml.split(','):
            current = current.strip()
            if not current:
                continue
            if '/' not in current:
                raise ValueError(f"Bad Service Item {current}")
            srv, proto = current.split('/', 1)
            srv, proto = srv.strip(), proto.strip()
            try:
                proto_num = normalize_proto(proto)
            except OSError:
                raise ValueError(f"Unknown protocol {proto}")
            protosym = getprotobynumber(proto_num) or str(proto_num)

            if '-' in srv or srv.isdigit():
                start, end = (map(int, srv.split('-')) if '-' in srv else (int(srv), int(srv)))
                start, end = int(start), int(end)
                if end < start:
                    raise ValueError(f"Bad range {start} - {end}")
                for i in range(start, end + 1):
                    servsym = safe_getservbyport(i, proto_num) or str(i)
                    app_key = f"{protosym}_{servsym}"
                    ref.setdefault('application', {})[app_key] = {}
                    ref.setdefault('service', {}).setdefault(proto_num, {})[i] = ref['application'][app_key]
            else:
                if not srv.isdigit():
                    servname = getprotobynumber(proto_num)
                    try:
                        srv_num = socket.getservbyname(srv, servname) if servname else socket.getservbyname(srv)
                    except OSError:
                        raise ValueError(f"Unknown service {srv}")
                else:
                    srv_num = int(srv)
                servsym = safe_getservbyport(srv_num, proto_num) or str(srv_num)
                app_key = f"{protosym}_{servsym}"
                ref.setdefault('application', {})[app_key] = {}
                ref.setdefault('service', {}).setdefault(proto_num, {})[srv_num] = ref['application'][app_key]

    def push_applications(self, refxml: Dict, ref: Dict):
        for app_name, app_data in refxml.items():
            ref.setdefault('application', {})[app_name] = {}
            content = (app_data or {}).get('content', '') or ''
            for current in content.split(','):
                current = current.strip()
                if not current:
                    continue
                if '/' not in current:
                    raise ValueError(f"Bad Service Item {current}")
                srv, proto = current.split('/', 1)
                srv, proto = srv.strip(), proto.strip()
                try:
                    proto_num = normalize_proto(proto)
                except OSError:
                    raise ValueError(f"Unknown protocol {proto}")

                if '-' in srv or srv.isdigit():
                    start, end = (map(int, srv.split('-')) if '-' in srv else (int(srv), int(srv)))
                    start, end = int(start), int(end)
                    if end < start:
                        raise ValueError(f"Bad range {start} - {end}")
                    for i in range(start, end + 1):
                        ref.setdefault('service', {}).setdefault(proto_num, {})[i] = ref['application'][app_name]
                else:
                    if not srv.isdigit():
                        servname = getprotobynumber(proto_num)
                        try:
                            srv_num = socket.getservbyname(srv, servname) if servname else socket.getservbyname(srv)
                        except OSError:
                            raise ValueError(f"Unknown service {srv}")
                    else:
                        srv_num = int(srv)
                    ref.setdefault('service', {}).setdefault(proto_num, {})[srv_num] = ref['application'][app_name]

    def push_directions(self, refxml: Dict, ref: Dict):
        for direction, dir_data in refxml.items():
            print(f"DIRECTION: {direction}")
            ref[direction] = {'name': direction}
            ref[direction]['samplerate'] = float(dir_data.get('samplerate', 1))

            subnet_fields = ['fromsubnets', 'tosubnets', 'nofromsubnets', 'notosubnets']
            subnet_lists = {f: [] for f in subnet_fields}

            for field in subnet_fields:
                if field in dir_data:
                    ref[direction][field] = self._create_trie()
                    for subnet in dir_data[field].split(','):
                        print(f"Adding {field} subnet {subnet}")
                        subnet_lists[field].append(subnet)
                        self.mylist['triesubnets'].append({'subnet': subnet, 'type': 'included' if 'no' not in field else 'excluded'})
                        ref[direction][field].add_string(subnet)

            for field, opposite in [('from', 'nofrom'), ('to', 'noto')]:
                if field in dir_data:
                    ref[direction].setdefault('fromsubnets' if field == 'from' else 'tosubnets', self._create_trie())
                    ref[direction].setdefault('nofromsubnets' if field == 'from' else 'notosubnets', self._create_trie())
                    print(f"Adding {field}subnets {dir_data[field]}")
                    for site in dir_data[field].split(','):
                        print(f"Adding {field}site {site}")
                        for subnet in self.config['sites']['site'][site]['subnets'].split(','):
                            print(f"Adding {field}subnets subnet {subnet}")
                            subnet_lists[field + 'subnets'].append(subnet)
                            self.mylist['triesubnets'].append({'subnet': subnet, 'type': 'included'})
                            ref[direction][field + 'subnets'].add_string(subnet)
                        for subnet in self.config['sites']['site'][site]['nosubnets'].split(','):
                            print(f"Adding no{field}subnets subnet {subnet}")
                            subnet_lists[f"no{field}subnets"].append(subnet)
                            self.mylist['triesubnets'].append({'subnet': subnet, 'type': 'excluded'})
                            ref[direction][f"no{field}subnets"].add_string(subnet)
                if opposite in dir_data:
                    ref[direction].setdefault('fromsubnets' if opposite == 'nofrom' else 'tosubnets', self._create_trie())
                    ref[direction].setdefault('nofromsubnets' if opposite == 'nofrom' else 'notosubnets', self._create_trie())
                    print(f"Adding no{field}subnets {dir_data[opposite]}")
                    for site in dir_data[opposite].split(','):
                        print(f"Adding no{field}site {site}")
                        for subnet in self.config['sites']['site'][site]['nosubnets'].split(','):
                            print(f"Adding {field}subnets subnet {subnet}")
                            subnet_lists[field + 'subnets'].append(subnet)
                            self.mylist['triesubnets'].append({'subnet': subnet, 'type': 'included'})
                            ref[direction][field + 'subnets'].add_string(subnet)
                        for subnet in self.config['sites']['site'][site]['subnets'].split(','):
                            print(f"Adding no{field}subnets subnet {subnet}")
                            subnet_lists[f"no{field}subnets"].append(subnet)
                            self.mylist['triesubnets'].append({'subnet': subnet, 'type': 'excluded'})
                            ref[direction][f"no{field}subnets"].add_string(subnet)

            if subnet_lists['nofromsubnets'] and not subnet_lists['fromsubnets']:
                print("Adding fromsubnet 0.0.0.0/0 implicit")
                subnet_lists['fromsubnets'].append("0.0.0.0/0")
                self.mylist['triesubnets'].append({'subnet': "0.0.0.0/0", 'type': 'included'})
                ref[direction].setdefault('fromsubnets', self._create_trie()).add_string("0.0.0.0/0")

            if subnet_lists['notosubnets'] and not subnet_lists['tosubnets']:
                print("Adding tosubnet 0.0.0.0/0 implicit")
                subnet_lists['tosubnets'].append("0.0.0.0/0")
                self.mylist['triesubnets'].append({'subnet': "0.0.0.0/0", 'type': 'included'})
                ref[direction].setdefault('tosubnets', self._create_trie()).add_string("0.0.0.0/0")

            for from_subnet in subnet_lists['fromsubnets']:
                for to_subnet in subnet_lists['tosubnets']:
                    print(f"Subnets: FROM={from_subnet} TO={to_subnet}")
                    subnet_list = self.mylist['subnets'].setdefault(from_subnet, {}).setdefault(to_subnet, [])
                    subnet_list.append({
                        'nofromsubnets': subnet_lists['nofromsubnets'],
                        'notosubnets': subnet_lists['notosubnets'],
                        'ref': ref[direction]
                    })

            if 'routergroup' in dir_data and 'fromas' in dir_data and 'toas' in dir_data:
                for from_as in dir_data['fromas'].split(','):
                    for to_as in dir_data['toas'].split(','):
                        print(f"Adding fromAS {from_as} toAS {to_as} to Direction {direction}")
                        ref[direction].setdefault('as', {}).setdefault(f"{from_as}:{to_as}", {})
                routergroup = dir_data['routergroup']
                print(f"Direction routergroup={routergroup}")
                for exporter in self.config['routergroups']['routergroup'][routergroup].get('router', []):
                    exp_ip = exporter['exporter']
                    print(f"Exporter: {exp_ip}, ")
                    ref[direction].setdefault('router', {}).setdefault(exp_ip, {})
                    if any(k in exporter for k in ['interface_in', 'interfaces_in', 'interface_out', 'interfaces_out']):
                        if 'countfunction' in ref[direction] and ref[direction]['countfunction'] != self.count_function_interfacesinout_withas:
                            raise RuntimeError("ERROR incorrect defined routergroup! Aborting")
                        ref[direction]['countfunction'] = self.count_function_interfacesinout_withas
                        ref[direction]['countfunctionname'] = "countFunction_interfacesinout_withas"
                        for key in ['interface_in', 'interface_out']:
                            if key in exporter:
                                print(f"{key}: {exporter[key]}")
                                ref[direction]['router'][exp_ip][key][exporter[key]] = {}
                        for key in ['interfaces_in', 'interfaces_out']:
                            if key in exporter:
                                print(f"{key}: ", end="")
                                for iface in exporter[key].split(','):
                                    print(f"+ interface {iface} ", end="")
                                    ref[direction]['router'][exp_ip][key][iface] = {}
                    if any(k in exporter for k in ['interface', 'interfaces']):
                        if 'countfunction' in ref[direction] and ref[direction]['countfunction'] != self.count_function_interfaces_withas:
                            raise RuntimeError("ERROR incorrect defined routergroup! Aborting")
                        ref[direction]['countfunction'] = self.count_function_interfaces_withas
                        ref[direction]['countfunctionname'] = "countFunction_interfaces_withas"
                        for key in ['interface']:
                            if key in exporter:
                                print(f"{key}: {exporter[key]}")
                                ref[direction]['router'][exp_ip][key][exporter[key]] = {}
                        for key in ['interfaces']:
                            if key in exporter:
                                print(f"{key}: ", end="")
                                for iface in exporter[key].split(','):
                                    print(f"+ interface {iface} ", end="")
                                    ref[direction]['router'][exp_ip][key][iface] = {}
                    if any(k in exporter for k in ['localsubnet', 'localsubnets']):
                        if 'countfunction' in ref[direction] and ref[direction]['countfunction'] != self.count_function_localsubnets_withas:
                            raise RuntimeError("ERROR incorrect defined routergroup! Aborting")
                        ref[direction]['countfunction'] = self.count_function_localsubnets_withas
                        ref[direction]['countfunctionname'] = "countFunction_localsubnets_withas"
                        ref[direction]['router'][exp_ip]['localsubnets'] = self._create_trie()
                        for key in ['localsubnet', 'localsubnets']:
                            if key in exporter:
                                print(f"{key}: {exporter[key]}")
                                for subnet in exporter[key].split(','):
                                    ref[direction]['router'][exp_ip]['localsubnets'].add_string(subnet)
                    print()
            elif 'routergroup' in dir_data:
                routergroup = dir_data['routergroup']
                print(f"Direction routergroup={routergroup}")
                for exporter in self.config['routergroups']['routergroup'][routergroup].get('router', []):
                    exp_ip = exporter['exporter']
                    print(f"Exporter: {exp_ip}, ")
                    ref[direction].setdefault('router', {}).setdefault(exp_ip, {})
                    if any(k in exporter for k in ['interface_in', 'interfaces_in', 'interface_out', 'interfaces_out']):
                        if 'countfunction' in ref[direction] and ref[direction]['countfunction'] != self.count_function_interfacesinout:
                            raise RuntimeError("ERROR incorrect defined routergroup! Aborting")
                        ref[direction]['countfunction'] = self.count_function_interfacesinout
                        ref[direction]['countfunctionname'] = "countFunction_interfacesinout"
                        for key in ['interface_in', 'interface_out']:
                            if key in exporter:
                                print(f"{key}: {exporter[key]}")
                                ref[direction]['router'][exp_ip][key][exporter[key]] = {}
                        for key in ['interfaces_in', 'interfaces_out']:
                            if key in exporter:
                                print(f"{key}: ", end="")
                                for iface in exporter[key].split(','):
                                    print(f"+ interface {iface} ", end="")
                                    ref[direction]['router'][exp_ip][key][iface] = {}
                    if any(k in exporter for k in ['interface', 'interfaces']):
                        if 'countfunction' in ref[direction] and ref[direction]['countfunction'] != self.count_function_interfaces:
                            raise RuntimeError("ERROR incorrect defined routergroup! Aborting")
                        ref[direction]['countfunction'] = self.count_function_interfaces
                        ref[direction]['countfunctionname'] = "countFunction_interfaces"
                        for key in ['interface']:
                            if key in exporter:
                                print(f"{key}: {exporter[key]}")
                                ref[direction]['router'][exp_ip][key][exporter[key]] = {}
                        for key in ['interfaces']:
                            if key in exporter:
                                print(f"{key}: ", end="")
                                for iface in exporter[key].split(','):
                                    print(f"+ interface {iface} ", end="")
                                    ref[direction]['router'][exp_ip][key][iface] = {}
                    if any(k in exporter for k in ['localsubnet', 'localsubnets']):
                        if 'countfunction' in ref[direction] and ref[direction]['countfunction'] != self.count_function_localsubnets:
                            raise RuntimeError("ERROR incorrect defined routergroup! Aborting")
                        ref[direction]['countfunction'] = self.count_function_localsubnets
                        ref[direction]['countfunctionname'] = "countFunction_localsubnets"
                        ref[direction]['router'][exp_ip]['localsubnets'] = self._create_trie()
                        for key in ['localsubnet', 'localsubnets']:
                            if key in exporter:
                                print(f"{key}: {exporter[key]}")
                                for subnet in exporter[key].split(','):
                                    ref[direction]['router'][exp_ip]['localsubnets'].add_string(subnet)
                    print()
            elif 'fromas' in dir_data and 'toas' in dir_data and not any(
                k in dir_data for k in ['routergroup', 'fromsubnets', 'tosubnets', 'nofromsubnets', 'notosubnets', 'from', 'to', 'nofrom', 'noto']
            ):
                for from_as in dir_data['fromas'].split(','):
                    for to_as in dir_data['toas'].split(','):
                        print(f"Adding fromAS {from_as} toAS {to_as} to Direction {direction}")
                        as_list = self.mylist['as'].setdefault(f"{from_as}:{to_as}", [])
                        as_list.append(ref[direction])
                ref[direction]['countfunction'] = self.count_function_pure
                ref[direction]['countfunctionname'] = "countFunction_pure"
            elif 'fromas' in dir_data and 'toas' in dir_data:
                for from_as in dir_data['fromas'].split(','):
                    for to_as in dir_data['toas'].split(','):
                        print(f"Adding fromAS {from_as} toAS {to_as} to Direction {direction}")
                        ref[direction].setdefault('as', {}).setdefault(f"{from_as}:{to_as}", {})
                ref[direction]['countfunction'] = self.count_function_withas
                ref[direction]['countfunctionname'] = "countFunction_withas"
            else:
                ref[direction]['countfunction'] = self.count_function_pure
                ref[direction]['countfunctionname'] = "countFunction_pure"

            if 'routergroup' in dir_data and not any(
                k in dir_data for k in ['fromsubnets', 'tosubnets', 'nofromsubnets', 'notosubnets', 'from', 'to', 'nofrom', 'noto']
            ):
                self.directionroutersgroupsonly = True
                routergroup = dir_data['routergroup']
                rg_list = self.mylist['routergroup'].setdefault(routergroup, [])
                print(f"Assign routergroup {routergroup} to Direction {direction}")
                rg_list.append(ref[direction])

            print(f"Assigning countfunction {ref[direction]['countfunctionname']} to direction {direction}")
            self.parse_direction(dir_data, ref[direction])
            self.generate_count_packets(ref[direction])

    def push_directions3(self, subnetlist: List[Dict], ref: Any):
        """Organize subnets into a trie for efficient matching."""
        # Sort subnets by prefix length (longer prefixes first)
        sortedlist = sorted(
            subnetlist,
            key=lambda x: int(x['subnet'].split('/')[1]) if '/' in x['subnet'] else 32
        )

        # Remove duplicates based on subnet and type
        seen = set()
        sortedlist = [
            item for item in sortedlist
            if not (item['subnet'] + item['type'] in seen or seen.add(item['subnet'] + item['type']))
        ]

        for addsubnet in sortedlist:
            subnet = addsubnet['subnet']
            subnet_type = addsubnet['type']
            # Get existing included/excluded lists for this subnet
            existing = ref.match_string(subnet) or {'included': [], 'excluded': []}
            included_list = existing['included'].copy()
            excluded_list = existing['excluded'].copy()

            # Update lists based on subnet type
            if subnet_type == 'included':
                included_list = list(set(included_list + [subnet]))
            else:
                excluded_list = list(set(excluded_list + [subnet]))

            # Add subnet to trie with updated lists
            ref.add_string(subnet, {'included': included_list, 'excluded': excluded_list})

    def create_wanted(self):
        """Generate the wanted function to process NetFlow records."""
        def wanted(self):
            """Process a single NetFlow record."""
            # Access flow variables (mocked from Cflow)
            srcaddr = Cflow.flowvars['srcaddr']
            dstaddr = Cflow.flowvars['dstaddr']
            src_as = Cflow.flowvars['src_as']
            dst_as = Cflow.flowvars['dst_as']
            exporterip = Cflow.flowvars['exporterip']
            input_if = Cflow.flowvars['input_if']
            output_if = Cflow.flowvars['output_if']

            # Backup servicecounted for 'all' and 'other' directions
            backup_servicecounted = self.servicescounted

            # Counting ALL with localsubnets
            if 'all' in self.mylist and 'localsubnets' in self.mylist['all']:
                if (self.mylist['all']['localsubnets'].match_integer(srcaddr) and
                        not self.mylist['all']['localsubnets'].match_integer(dstaddr)):
                    self.mylist['all']['countpackets'](self.mylist['all'], 'out')
                if (self.mylist['all']['localsubnets'].match_integer(dstaddr) and
                        not self.mylist['all']['localsubnets'].match_integer(srcaddr)):
                    self.mylist['all']['countpackets'](self.mylist['all'], 'in')
                self.servicescounted = backup_servicecounted

            # Counting ALL without localsubnets (assume outbound)
            if 'all' in self.mylist and 'localsubnets' not in self.mylist['all']:
                self.mylist['all']['countpackets'](self.mylist['all'], 'out')
                self.servicescounted = backup_servicecounted

            # Counting for Routers with router groups
            routers = self.mylist.get('routers', {}).get('router', {})
            if self.directionroutersgroupsonly and exporterip in routers:
                router = routers[exporterip]
                if output_if in router:
                    for routergroup in router[output_if].get('routergroups', []):
                        for ref in self.mylist['routergroup'].get(routergroup, []):
                            ref['countfunction'](ref, 'out')
                if input_if in router:
                    for routergroup in router[input_if].get('routergroups', []):
                        for ref in self.mylist['routergroup'].get(routergroup, []):
                            ref['countfunction'](ref, 'in')
                if 'localsubnets' in router:
                    if (router['localsubnets'].match_integer(dstaddr) and
                            not router['localsubnets'].match_integer(srcaddr)):
                        for routergroup in router.get('routergroups', []):
                            for ref in self.mylist['routergroup'].get(routergroup, []):
                                ref['countfunction'](ref, 'in')
                    if (router['localsubnets'].match_integer(srcaddr) and
                            not router['localsubnets'].match_integer(dstaddr)):
                        for routergroup in router.get('routergroups', []):
                            for ref in self.mylist['routergroup'].get(routergroup, []):
                                ref['countfunction'](ref, 'out')

            # Counting for AS-based directions
            if 'as' in self.mylist:
                if f"{src_as}:{dst_as}" in self.mylist['as']:
                    for ref in self.mylist['as'][f"{src_as}:{dst_as}"]:
                        ref['countfunction'](ref, 'out')
                if f"{dst_as}:{src_as}" in self.mylist['as']:
                    for ref in self.mylist['as'][f"{dst_as}:{src_as}"]:
                        ref['countfunction'](ref, 'in')

            # Count directions (handles subnet-based directions)
            self.count_directions()

            return True

        # Bind the wanted function to the instance
        self.wanted = wanted.__get__(self, JKFlow)
        print("Wanted function created")

    def new(self):
        """Initialize a new JKFlow instance."""
        return JKFlow()

    def _init(self):
        """Internal initialization (called by new)."""
        return self

    def perfile(self, *args):
        """Called once per flow file to reset totals."""
        self.totals = {}
        super().perfile(*args)

    def reporttorrd(self, dir: str, name: str, ref: Dict, samplerate: float):
        """Generate and update RRD files."""
        # lstrip: a leading '/' in dir would make os.path.join discard RRDDIR and
        # write to the filesystem root. Sub-paths are always relative to RRDDIR.
        file = os.path.join(self.RRDDIR, dir.lstrip('/'), name)
        if not os.path.exists(file):
            print(f"Creating RRD-File {file}")
            self.createGeneralRRD(file, [
                'ABSOLUTE', 'in_bytes',
                'ABSOLUTE', 'out_bytes',
                'ABSOLUTE', 'in_pkts',
                'ABSOLUTE', 'out_pkts',
                'ABSOLUTE', 'in_flows',
                'ABSOLUTE', 'out_flows'
            ])

        values = []
        for metric in ['bytes', 'pkts', 'flows']:
            for direction in ['in', 'out']:
                value = ref.get(direction, {}).get(metric, 0) * samplerate
                values.append(value)
                ref.setdefault(direction, {})[metric] = 0
        self.updateRRD(dir, name, values)
        # print(f"File: {dir} {name} {values}")

    def reporttorrdfiles(self, dir: str, ref: Dict, samplerate: float):
        """Recursively generate RRD files for all metrics."""
        dir = dir.lstrip('/')
        dir_path = os.path.join(self.RRDDIR, dir)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path, mode=0o755)

        if 'total' in ref:
            self.reporttorrd(dir, "total.rrd", ref['total'], samplerate)

        if 'tos' in ref:
            for tos in ref['tos']:
                self.reporttorrd(dir, f"tos_{tos}.rrd", ref['tos'][tos], samplerate)

        if 'dscp' in ref:
            for dscp in ref['dscp']:
                self.reporttorrd(dir, f"tos_{dscp}.rrd", ref['dscp'][dscp], samplerate)

        if 'multicast' in ref:
            self.reporttorrd(dir, "protocol_multicast.rrd", ref['multicast'].get('total', {}), samplerate)

        if 'protocol' in ref:
            for protocol in ref['protocol']:
                proto_name = 'other' if protocol == 'other' else (getprotobynumber(int(protocol)) or str(protocol))
                self.reporttorrd(dir, f"protocol_{proto_name}.rrd", ref['protocol'][protocol].get('total', {}), samplerate)

        if 'application' in ref:
            for src in ['src', 'dst']:
                for application in ref['application']:
                    self.reporttorrd(dir, f"service_{application}_{src}.rrd", ref['application'][application].get(src, {}), samplerate)

        if 'ftp' in ref:
            for src in ['src', 'dst']:
                self.reporttorrd(dir, f"service_ftp_{src}.rrd", ref['ftp'].get(src, {}), samplerate)
            for pair in list(ref['ftp'].get('cache', {})):
                timediff = self.filetime - ref['ftp']['cache'][pair]
                if timediff > 2 * 60 * 60 or timediff < -15 * 60:
                    # print(f"Deleted FTP-session: {pair} Timediff: {timediff}")
                    del ref['ftp']['cache'][pair]

        if 'scoreboard' in ref:
            score_dir = os.path.join(self.SCOREDIR, dir)
            if not os.path.exists(score_dir):
                os.makedirs(score_dir, mode=0o755)
            self.scoreboard(dir, ref['scoreboard'], samplerate)

        if 'scoreboardother' in ref:
            score_dir = os.path.join(self.SCOREDIR, dir)
            other_dir = os.path.join(score_dir, "other")
            if not os.path.exists(score_dir):
                os.makedirs(score_dir, mode=0o755)
            if not os.path.exists(other_dir):
                os.makedirs(other_dir, mode=0o755)
            self.scoreboard(os.path.join(dir, "other"), ref['scoreboardother'], samplerate)

        if 'direction' in ref:
            for direction in ref['direction']:
                self.reporttorrdfiles(os.path.join(dir, direction), ref['direction'][direction], ref['direction'][direction]['samplerate'])

    def report(self):
        """Generate all reports."""
        if 'all' in self.mylist:
            self.reporttorrdfiles("all", self.mylist['all'], self.mylist['all']['samplerate'])
        for direction in self.mylist['direction']:
            self.reporttorrdfiles(direction, self.mylist['direction'][direction], self.mylist['direction'][direction]['samplerate'])

    def updateRRD(self, dir: str, name: str, values: List[float]):
        """Update an RRD file with new values."""
        if rrdtool is None:
            return
        file = os.path.join(self.RRDDIR, dir.lstrip('/'), name)
        timestamp = getattr(self, 'filetime', int(datetime.datetime.now().timestamp()))
        try:
            rrdtool.update(file, f"{timestamp}:{':'.join(map(str, values))}")
        except Exception as e:
            logging.warning(f"ERROR updating {file}: {e}")

    def scoreboard(self, dir: str, ref: Dict, samplerate: float):
        """Generate HTML scoreboard reports."""
        dir = dir.lstrip('/')
        filetime = getattr(self, 'filetime', int(time.time()))
        dt = datetime.datetime.fromtimestamp(filetime)
        year, mon, mday, hour, min_, sec = dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second

        newaggdata = {}

        if 'every' in ref:
            file_dir = os.path.join(self.SCOREDIR, dir, 'html', f"{year:04d}-{mon:02d}-{mday:02d}")
            os.makedirs(file_dir, mode=0o755, exist_ok=True)
            file = os.path.join(file_dir, f"{hour:02d}:{min_:02d}:{sec:02d}.html")
            html_content = "<html>\n<body bgcolor=\"#ffffff\">\n<center>\n\n"

        def cnt(tk, metric, d):
            return ref.get('count', {}).get(tk, {}).get(metric, {}).get(d, 0)

        scorekeep = ref.get('scorekeep', self.SCOREKEEP)

        for direction in ['out', 'in']:
            for key in ['bytes', 'pkts', 'flows']:
                sorted_keys = sorted(
                    ref.get('count', {}),
                    key=lambda x: cnt(x, key, direction),
                    reverse=True
                )

                table_data = [
                    ['rank', 'Tuple', 'Tuplekey', 'bits/sec out', 'bits/sec in',
                     'pkts/sec out', 'pkts/sec in', 'flows/sec out', 'flows/sec in']
                ]
                for i, tuplekey in enumerate(sorted_keys[:scorekeep]):
                    # tuplekey is the joined value string; ref['tuple'][tuplekey]
                    # holds the original expression (matches JKFlow.pm).
                    if 'every' in ref:
                        table_data.append([
                            f"#{i+1}",
                            ref.get('tuple', {}).get(tuplekey, tuplekey),
                            tuplekey,
                            self.scale("%.1f", (cnt(tuplekey, 'bytes', 'out') * 8) / self.SAMPLETIME),
                            self.scale("%.1f", (cnt(tuplekey, 'bytes', 'in') * 8) / self.SAMPLETIME),
                            self.scale("%.1f", cnt(tuplekey, 'pkts', 'out') / self.SAMPLETIME),
                            self.scale("%.1f", cnt(tuplekey, 'pkts', 'in') / self.SAMPLETIME),
                            self.scale("%.1f", cnt(tuplekey, 'flows', 'out') / self.SAMPLETIME),
                            self.scale("%.1f", cnt(tuplekey, 'flows', 'in') / self.SAMPLETIME),
                        ])

                    # Populated for EVERY sample (not only when 'every' is set) so
                    # aggregate reports work, exactly as JKFlow.pm does.
                    if tuplekey not in newaggdata:
                        newaggdata[tuplekey] = {
                            'tuple': ref.get('tuple', {}).get(tuplekey, tuplekey),
                            'bytesout': cnt(tuplekey, 'bytes', 'out') * samplerate,
                            'bytesin': cnt(tuplekey, 'bytes', 'in') * samplerate,
                            'pktsout': cnt(tuplekey, 'pkts', 'out') * samplerate,
                            'pktsin': cnt(tuplekey, 'pkts', 'in') * samplerate,
                            'flowsout': cnt(tuplekey, 'flows', 'out') * samplerate,
                            'flowsin': cnt(tuplekey, 'flows', 'in') * samplerate,
                        }

                if 'every' in ref and tabulate is not None:
                    table_html = tabulate(table_data, headers='firstrow',
                                          tablefmt='html', numalign='right')
                    caption = f"Top {scorekeep} by <b>{key} {direction}</b><br>\nfor flow sample ending {dt}"
                    html_content += f"<p><b>{caption}</b>\n{table_html}</p>\n\n"

        if 'every' in ref:
            html_content += "\n</center>\n</body>\n</html>\n"
            with open(file, 'w') as f:
                f.write(html_content)

            if 'latest' in ref:
                latest = os.path.join(self.SCOREDIR, dir, ref['latest'])
                if not ref['latest'].startswith('/'):
                    latest = os.path.join(self.SCOREDIR, dir, ref['latest'])
                try:
                    if os.path.exists(latest):
                        os.unlink(latest)
                    os.symlink(file, latest)
                except OSError as e:
                    logging.warning(f"Could not create symlink to {latest}: {e}")

        if 'aggregate' in ref and 'report' in ref['aggregate']:
            self.count_aggdata(dir, ref['aggregate']['report'], newaggdata, filetime)

        if 'count' in ref:
            del ref['count']
        if 'tuple' in ref:
            del ref['tuple']

    def count_aggdata(self, dir: str, ref: List[Dict], newaggdata: Dict, filetime: int):
        """Update aggregate scoreboard data."""
        dir = dir.lstrip('/')
        for report in ref:
            if filetime > report.get('startperiod', 0) + report['count'] * self.SAMPLETIME:
                if report.get('startperiod') == 0:
                    report['startperiod'] = filetime
                else:
                    dt = datetime.datetime.fromtimestamp(report['startperiod'])
                    file = f"{report['filenamebase']}-{dt.year:04d}-{dt.month:02d}-{dt.day:02d}-{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}.html"
                    if not file.startswith('/'):
                        file = os.path.join(self.SCOREDIR, dir, file)
                    self.write_agg_scoreboard(report['aggdata']['tuplevalues'], report['scorekeep'], report['counter'], file)
                    report['counter'] = 0
                    report['startperiod'] = filetime - ((filetime - report.get('offset', 0) * self.SAMPLETIME) % (report['count'] * self.SAMPLETIME))
                    if 'aggdata' in report:
                        del report['aggdata']

            for tuplekey in newaggdata:
                report.setdefault('aggdata', {}).setdefault('tuplevalues', {}).setdefault(tuplekey, {})
                report['aggdata']['tuplevalues'][tuplekey].setdefault('count', 0)
                report['aggdata']['tuplevalues'][tuplekey]['count'] += 1
                report['aggdata']['tuplevalues'][tuplekey]['tuple'] = newaggdata[tuplekey]['tuple']
                for metric in ['bytesout', 'bytesin', 'pktsout', 'pktsin', 'flowsout', 'flowsin']:
                    report['aggdata']['tuplevalues'][tuplekey].setdefault(metric, 0)
                    report['aggdata']['tuplevalues'][tuplekey][metric] += newaggdata[tuplekey][metric]
                report['aggdata'].setdefault('numresults', 0)
                report['aggdata']['numresults'] += 1

            if report['aggdata']['numresults'] > report['numkeep']:
                report['aggdata']['numresults'] >>= 1
                for tuplekey in list(report['aggdata']['tuplevalues']):
                    if report['aggdata']['tuplevalues'][tuplekey]['count'] == 1:
                        del report['aggdata']['tuplevalues'][tuplekey]
                    else:
                        report['aggdata']['tuplevalues'][tuplekey]['count'] >>= 1
                        for metric in ['bytesout', 'bytesin', 'pktsout', 'pktsin', 'flowsout', 'flowsin']:
                            report['aggdata']['tuplevalues'][tuplekey][metric] >>= 1
                report['counter'] = report.get('counter', 0) + 1

    def write_agg_scoreboard(self, data: Dict, scorekeep: int, count: int, file: str):
        """Write aggregate scoreboard HTML file."""
        html_content = "<html>\n<body bgcolor=\"#ffffff\">\n<center>\n"
        html_content += f"<h3> Average rankings for the last {count} topN reports\n<hr>\n</center>\n"

        for direction in ['out', 'in']:
            for key in ['bytes', 'pkts', 'flows']:
                sorted_keys = sorted(
                    data,
                    key=lambda x: (data[x][f"{key}{direction}"] / data[x]['count']),
                    reverse=True
                )
                table_data = [
                    ['rank', 'tuple', 'tuplekey', 'bits/sec out', 'bits/sec in',
                     'pkts/sec out', 'pkts/sec in', 'flows/sec out', 'flows/sec in']
                ]
                for i, tuplekey in enumerate(sorted_keys[:scorekeep]):
                    div = self.SAMPLETIME * data[tuplekey]['count']
                    row = [
                        f"#{i+1}",
                        data[tuplekey]['tuple'],
                        tuplekey,
                        self.scale("%.1f", (data[tuplekey]['bytesout'] * 8) / div),
                        self.scale("%.1f", (data[tuplekey]['bytesin'] * 8) / div),
                        self.scale("%.1f", data[tuplekey]['pktsout'] / div),
                        self.scale("%.1f", data[tuplekey]['pktsin'] / div),
                        self.scale("%.1f", data[tuplekey]['flowsout'] / div),
                        self.scale("%.1f", data[tuplekey]['flowsin'] / div)
                    ]
                    table_data.append(row)

                table_html = tabulate(
                    table_data,
                    headers='firstrow',
                    tablefmt='html',
                    numalign='right'
                )
                caption = f"Top {scorekeep} by <b>{key} {direction}</b><br>\nbuilt on aggregated topN average samples to date"
                html_content += f"<p><b>{caption}</b>\n{table_html}</p>\n\n"

        html_content += "</center>\n</body>\n</html>\n"
        os.makedirs(os.path.dirname(file), mode=0o755, exist_ok=True)
        with open(file, 'w') as f:
            f.write(html_content)

    def countftp(self, ref: Dict, which: str) -> bool:
        """Count FTP-related flows."""
        srcport = Cflow.flowvars['srcport']
        dstport = Cflow.flowvars['dstport']
        srcaddr = Cflow.flowvars['srcaddr']
        dstaddr = Cflow.flowvars['dstaddr']
        bytes = Cflow.flowvars['bytes']
        pkts = Cflow.flowvars['pkts']
        endtime = Cflow.flowvars['endtime']

        if (srcport == 21 or dstport == 21 or
                srcport == 20 or dstport == 20 or
                (srcport >= 1024 and dstport >= 1024)):
            if (srcport >= 1024 and dstport >= 1024) or srcport == 20 or dstport == 20:
                if f"{dstaddr}:{srcaddr}" in ref.get('cache', {}):
                    ref.setdefault('dst', {}).setdefault(which, {}).setdefault('flows', 0)
                    ref['dst'][which]['flows'] += 1
                    ref['dst'].setdefault(which, {}).setdefault('bytes', 0)
                    ref['dst'][which]['bytes'] += bytes
                    ref['dst'].setdefault(which, {}).setdefault('pkts', 0)
                    ref['dst'][which]['pkts'] += pkts
                    self.servicescounted = True
                    ref.setdefault('cache', {})[f"{dstaddr}:{srcaddr}"] = endtime
                    return True
                elif f"{srcaddr}:{dstaddr}" in ref.get('cache', {}):
                    ref.setdefault('src', {}).setdefault(which, {}).setdefault('flows', 0)
                    ref['src'][which]['flows'] += 1
                    ref['src'].setdefault(which, {}).setdefault('bytes', 0)
                    ref['src'][which]['bytes'] += bytes
                    ref['src'].setdefault(which, {}).setdefault('pkts', 0)
                    ref['src'][which]['pkts'] += pkts
                    self.servicescounted = True
                    ref.setdefault('cache', {})[f"{srcaddr}:{dstaddr}"] = endtime
                    return True
            elif dstport == 21:
                ref.setdefault('dst', {}).setdefault(which, {}).setdefault('flows', 0)
                ref['dst'][which]['flows'] += 1
                ref['dst'].setdefault(which, {}).setdefault('bytes', 0)
                ref['dst'][which]['bytes'] += bytes
                ref['dst'].setdefault(which, {}).setdefault('pkts', 0)
                ref['dst'][which]['pkts'] += pkts
                self.servicescounted = True
                ref.setdefault('cache', {})[f"{dstaddr}:{srcaddr}"] = endtime
                return True
            elif srcport == 21:
                ref.setdefault('src', {}).setdefault(which, {}).setdefault('flows', 0)
                ref['src'][which]['flows'] += 1
                ref['src'].setdefault(which, {}).setdefault('bytes', 0)
                ref['src'][which]['bytes'] += bytes
                ref['src'].setdefault(which, {}).setdefault('pkts', 0)
                ref['src'][which]['pkts'] += pkts
                self.servicescounted = True
                ref.setdefault('cache', {})[f"{srcaddr}:{dstaddr}"] = endtime
                return True
        return False

    def percent(self, num: float, denom: float) -> float:
        """Calculate percentage."""
        return 0 if denom == 0 else 100 * (num / denom)

    def scale(self, fmt: str, value: float) -> str:
        """Format a large number with sensible units."""
        symbols = ["a", "f", "p", "n", "u", "m", " ", "k", "M", "G", "T", "P", "E"]
        symbcenter = 6
        digits = 0 if value == 0 else math.floor(math.log(value) / math.log(1000))
        return f"{fmt % (value / (1000 ** digits))} {symbols[symbcenter + digits]}"

    def __del__(self):
        """Destructor."""
        pass
        #super().__del__()

    def count_function_pure(self, direction: Dict, which: str):
        """Count function for directions without routergroups."""
        direction['countpackets'](direction, which)

    def count_function_withas(self, direction: Dict, which: str):
        """Count function for directions without routergroups with AS."""
        src_as = Cflow.flowvars['src_as']
        dst_as = Cflow.flowvars['dst_as']
        if f"{src_as}:{dst_as}" in direction.get('as', {}):
            direction['countpackets'](direction, 'out')
        if f"{dst_as}:{src_as}" in direction.get('as', {}):
            direction['countpackets'](direction, 'in')

    def count_function_interfacesinout(self, direction: Dict, which: str):
        """Count function for directions with routergroups with only interfaces_in or interfaces_out defined."""
        exporterip = Cflow.flowvars['exporterip']
        input_if = Cflow.flowvars['input_if']
        output_if = Cflow.flowvars['output_if']
        if exporterip in direction.get('router', {}):
            router = direction['router'][exporterip]
            if 'interface_out' in router:
                if input_if in router['interface_out']:
                    direction['countpackets'](direction, 'in')
                if output_if in router['interface_out']:
                    direction['countpackets'](direction, 'out')
            if 'interface_in' in router:
                if input_if in router['interface_in']:
                    direction['countpackets'](direction, 'out')
                if output_if in router['interface_in']:
                    direction['countpackets'](direction, 'in')

    def count_function_interfacesinout_withas(self, direction: Dict, which: str):
        """Count function for directions with routergroups with interfaces_in/interfaces_out and AS defined."""
        exporterip = Cflow.flowvars['exporterip']
        input_if = Cflow.flowvars['input_if']
        output_if = Cflow.flowvars['output_if']
        src_as = Cflow.flowvars['src_as']
        dst_as = Cflow.flowvars['dst_as']
        if exporterip in direction.get('router', {}) and (f"{src_as}:{dst_as}" in direction.get('as', {}) or f"{dst_as}:{src_as}" in direction.get('as', {})):
            router = direction['router'][exporterip]
            if 'interface_out' in router:
                if input_if in router['interface_out']:
                    direction['countpackets'](direction, 'in')
                if output_if in router['interface_out']:
                    direction['countpackets'](direction, 'out')
            if 'interface_in' in router:
                if input_if in router['interface_in']:
                    direction['countpackets'](direction, 'out')
                if output_if in router['interface_in']:
                    direction['countpackets'](direction, 'in')

    def count_function_interfaces(self, direction: Dict, which: str):
        """Count function for directions with routergroups with interfaces defined."""
        exporterip = Cflow.flowvars['exporterip']
        input_if = Cflow.flowvars['input_if']
        output_if = Cflow.flowvars['output_if']
        if exporterip in direction.get('router', {}):
            router = direction['router'][exporterip]
            if 'interface' in router and (input_if in router['interface'] or output_if in router['interface']):
                direction['countpackets'](direction, which)

    def count_function_interfaces_withas(self, direction: Dict, which: str):
        """Count function for directions with routergroups with interfaces and AS defined."""
        exporterip = Cflow.flowvars['exporterip']
        input_if = Cflow.flowvars['input_if']
        output_if = Cflow.flowvars['output_if']
        src_as = Cflow.flowvars['src_as']
        dst_as = Cflow.flowvars['dst_as']
        if f"{src_as}:{dst_as}" in direction.get('as', {}):
            if exporterip in direction.get('router', {}):
                router = direction['router'][exporterip]
                if 'interface' in router and (input_if in router['interface'] or output_if in router['interface']):
                    direction['countpackets'](direction, 'out')
        if f"{dst_as}:{src_as}" in direction.get('as', {}):
            if exporterip in direction.get('router', {}):
                router = direction['router'][exporterip]
                if 'interface' in router and (input_if in router['interface'] or output_if in router['interface']):
                    direction['countpackets'](direction, 'in')

    def count_function_localsubnets(self, direction: Dict, which: str):
        """Count function for directions with routergroups with localsubnets defined."""
        exporterip = Cflow.flowvars['exporterip']
        srcaddr = Cflow.flowvars['srcaddr']
        dstaddr = Cflow.flowvars['dstaddr']
        if exporterip in direction.get('router', {}):
            router = direction['router'][exporterip]
            if 'localsubnets' in router:
                if router['localsubnets'].match_integer(dstaddr) and not router['localsubnets'].match_integer(srcaddr):
                    direction['countpackets'](direction, 'in')
                if router['localsubnets'].match_integer(srcaddr) and not router['localsubnets'].match_integer(dstaddr):
                    direction['countpackets'](direction, 'out')

    def count_function_localsubnets_withas(self, direction: Dict, which: str):
        """Count function for directions with routergroups with localsubnets and AS defined."""
        exporterip = Cflow.flowvars['exporterip']
        srcaddr = Cflow.flowvars['srcaddr']
        dstaddr = Cflow.flowvars['dstaddr']
        src_as = Cflow.flowvars['src_as']
        dst_as = Cflow.flowvars['dst_as']
        as_map = direction.get('as', {})
        if f"{src_as}:{dst_as}" in as_map or f"{dst_as}:{src_as}" in as_map:
            router = direction.get('router', {}).get(exporterip)
            if router and 'localsubnets' in router:
                ls = router['localsubnets']
                if ls.match_integer(dstaddr) and not ls.match_integer(srcaddr):
                    direction['countpackets'](direction, 'in')
                if ls.match_integer(srcaddr) and not ls.match_integer(dstaddr):
                    direction['countpackets'](direction, 'out')

    def generate_count_packets(self, ref: Dict):
        def count_packets(ref: Dict, which: str):
            protocol = Cflow.flowvars['protocol']
            tos = Cflow.flowvars['tos']
            dstaddr = Cflow.flowvars['dstaddr']
            bytes = Cflow.flowvars['bytes']
            pkts = Cflow.flowvars['pkts']
            dstport = Cflow.flowvars['dstport']
            srcport = Cflow.flowvars['srcport']

            def bump(node):
                """Increment flows/bytes/pkts on node[which] (autovivifying)."""
                d = node.get(which)
                if d is None:
                    d = node[which] = {'flows': 0, 'bytes': 0, 'pkts': 0}
                d['flows'] += 1
                d['bytes'] += bytes
                d['pkts'] += pkts

            def _score_tuples(ref, board, which):
                """Accumulate scoreboard tuple counters (board = 'scoreboard' or
                'scoreboardother'). Tuple expressions are Python lists over the
                flow variables, e.g. '[srcaddr,dstport]'."""
                b = ref.get(board)
                if not b or 'tuples' not in b:
                    return
                count = b.setdefault('count', {})
                tup = b.setdefault('tuple', {})
                for expr in b['tuples']:
                    try:
                        values = eval(expr, {'__builtins__': {}}, Cflow.flowvars)
                    except Exception:
                        continue
                    key = '-'.join(map(str, values))
                    slot = count.setdefault(key, {'flows': {}, 'bytes': {}, 'pkts': {}})
                    slot['flows'][which] = slot['flows'].get(which, 0) + 1
                    slot['bytes'][which] = slot['bytes'].get(which, 0) + bytes
                    slot['pkts'][which] = slot['pkts'].get(which, 0) + pkts
                    tup[key] = expr

            if 'total' in ref:
                bump(ref['total'])

            if 'tos' in ref:
                typeos = "BE" if tos == 0 else "other"
                bump(ref['tos'].setdefault(typeos, {}))

            if 'dscp' in ref:
                if tos == 0:
                    typeos = "BE"
                else:
                    class_ = tos >> 5
                    drop = (tos >> 3) & 0x03
                    if 0 < class_ < 5 and drop > 0:
                        typeos = f"AF{class_}{drop}"
                    elif drop == 0:
                        typeos = f"CS{class_}"
                    elif class_ == 5 and drop == 3:
                        typeos = "EF"
                    else:
                        typeos = "other"
                bump(ref['dscp'].setdefault(typeos, {}))

            if 'multicast' in ref:
                if (dstaddr & self.MCAST_MASK) == self.MCAST_NET:
                    bump(ref['multicast'].setdefault('total', {}))

            if 'protocol' in ref:
                if protocol in ref['protocol']:
                    bump(ref['protocol'][protocol].setdefault('total', {}))
                elif 'other' in ref['protocol']:
                    bump(ref['protocol']['other'].setdefault('total', {}))

            # --- Services / applications -------------------------------------
            # Faithful to JKFlow.pm's generated elsif chain: try dst service,
            # then src service, then (depending on what's configured) FTP and/or
            # the catch-all 'other' application.
            if 'service' in ref:
                svc = ref['service'].get(protocol)
                if svc is not None:
                    counted = False
                    application = svc.get(dstport)
                    if application is not None:
                        bump(application.setdefault('dst', {}))
                        self.servicescounted = True
                        counted = True
                    else:
                        application = svc.get(srcport)
                        if application is not None:
                            bump(application.setdefault('src', {}))
                            self.servicescounted = True
                            counted = True

                    if not counted:
                        has_ftp = 'ftp' in ref
                        has_other = 'application' in ref and 'other' in ref['application']
                        # Perl: ftp+other -> elsif(countftp){}else{other};
                        #       ftp only  -> else{countftp};
                        #       other only-> else{other}
                        if has_ftp and has_other:
                            if not self.countftp(ref['ftp'], which):
                                bump(ref['application']['other'].setdefault('dst', {}))
                                self.servicescounted = True
                                _score_tuples(ref, 'scoreboardother', which)
                        elif has_ftp:
                            self.countftp(ref['ftp'], which)
                        elif has_other:
                            bump(ref['application']['other'].setdefault('dst', {}))
                            self.servicescounted = True
                            _score_tuples(ref, 'scoreboardother', which)

            if 'service' not in ref and 'ftp' in ref:
                self.countftp(ref['ftp'], which)

            _score_tuples(ref, 'scoreboard', which)

            if ref.get('monitor') == "yes":
                print("SRC=%s, SPORT=%s, DST=%s, DPORT=%s, EXP=%s" % (
                    socket.inet_ntoa(struct.pack('!I', Cflow.flowvars['srcaddr'])), srcport,
                    socket.inet_ntoa(struct.pack('!I', Cflow.flowvars['dstaddr'])), dstport,
                    socket.inet_ntoa(struct.pack('!I', Cflow.flowvars['exporterip']))))

        ref['countpackets'] = count_packets

        if ref['countpackets'] is None:
            print("There was a problem with this autogenerated packet evaluation function:")
            # Print the equivalent code
            exit(1)

    # count_directions function
    def count_directions(self):
        """Handle counting for subnet-based directions."""
        srcaddr = Cflow.flowvars['srcaddr']
        dstaddr = Cflow.flowvars['dstaddr']

        srctriematch = self.trie.match_integer(srcaddr)
        dsttriematch = self.trie.match_integer(dstaddr)

        if srctriematch and dsttriematch and 'included' in srctriematch and 'included' in dsttriematch:
            srcsubnets = srctriematch['included']
            dstsubnets = dsttriematch['included']
            for srcsubnet in srcsubnets:
                for dstsubnet in dstsubnets:
                    if srcsubnet in self.mylist.get('subnets', {}) and dstsubnet in self.mylist['subnets'][srcsubnet]:
                        for direction in self.mylist['subnets'][srcsubnet][dstsubnet]:
                            excluded_src = srctriematch.get('excluded', []) + direction.get('nofromsubnets', [])
                            excluded_dst = dsttriematch.get('excluded', []) + direction.get('notosubnets', [])
                            # Check for no duplicates (Perl uses grep ++$i{$_} > 1 to check overlaps)
                            if len(set(excluded_src)) == len(excluded_src) and len(set(excluded_dst)) == len(excluded_dst):
                                direction['ref']['countfunction'](direction['ref'], 'out')
                    if dstsubnet in self.mylist.get('subnets', {}) and srcsubnet in self.mylist['subnets'][dstsubnet]:
                        for direction in self.mylist['subnets'][dstsubnet][srcsubnet]:
                            excluded_src = srctriematch.get('excluded', []) + direction.get('notosubnets', [])
                            excluded_dst = dsttriematch.get('excluded', []) + direction.get('nofromsubnets', [])
                            if len(set(excluded_src)) == len(excluded_src) and len(set(excluded_dst)) == len(excluded_dst):
                                direction['ref']['countfunction'](direction['ref'], 'in')

        if 'direction' in self.mylist and 'other' in self.mylist['direction'] and not self.servicescounted:
            self.mylist['direction']['other']['countfunction'](self.mylist['direction']['other'], 'out')

        self.servicescounted = False

# =============================================================================
# Flow record intake
#
# JKFlow.pm got its records from the Perl Cflow/FlowScan layer reading cflowd
# binary files. That capture format is long dead; this port reads modern
# nfdump/nfcapd files instead. nfdump emits a stable CSV (with a header row), so
# we map columns by NAME rather than position -- robust across nfdump versions.
#
# The reader yields one dict per flow with exactly the keys Cflow.flowvars uses;
# the driver mutates Cflow.flowvars in place (never reassigns it) so every
# counting closure keeps seeing the same object, matching the Perl globals.
# =============================================================================

# Canonical flow field -> candidate nfdump CSV column names, in priority order.
# nfdump's `-o csv` header changed between versions: 1.7 emits verbose names
# (firstSeen, proto, srcAddr, srcPort, dstAddr, dstPort, packets, bytes, ...),
# while older builds used terse ones (ts, pr, sa, sp, da, dp, ipkt, ibyt, ...).
# We resolve each field against whatever header is actually present, so both
# work. Fields absent from a given format (exporter/AS/interface/tos for locally
# captured nfpcapd flows) simply default to 0.
_CSV_ALIASES = {
    'srcaddr':    ['sa', 'srcAddr', 'srcaddr', 'src_addr'],
    'dstaddr':    ['da', 'dstAddr', 'dstaddr', 'dst_addr'],
    'srcport':    ['sp', 'srcPort', 'srcport', 'src_port'],
    'dstport':    ['dp', 'dstPort', 'dstport', 'dst_port'],
    'protocol':   ['pr', 'proto', 'protocol'],
    'bytes':      ['ibyt', 'byt', 'bytes', 'obyt', 'in_bytes'],
    'pkts':       ['ipkt', 'pkt', 'packets', 'opkt', 'in_packets'],
    'tos':        ['stos', 'tos', 'dtos'],
    'input_if':   ['in', 'input', 'in_if'],
    'output_if':  ['out', 'output', 'out_if'],
    'src_as':     ['sas', 'srcas', 'src_as'],
    'dst_as':     ['das', 'dstas', 'dst_as'],
    'exporterip': ['ra', 'router', 'exporter'],
    '_start':     ['ts', 'firstSeen', 'tstart', 'first'],
    '_end':       ['te', 'lastSeen', 'tend', 'last'],
    '_dur':       ['td', 'duration', 'dur'],
}


def _ip_to_int(value: str) -> Optional[int]:
    """Dotted-quad -> 32-bit int. Returns None for IPv6 or junk (IPv4-only port)."""
    value = (value or '').strip()
    if not value or ':' in value:
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    return int(addr) if addr.version == 4 else None


def _parse_time(value: str) -> int:
    """nfdump timestamp ('YYYY-MM-DD HH:MM:SS[.mmm]') -> epoch seconds."""
    value = (value or '').strip()
    if not value:
        return 0
    if value.isdigit():
        return int(value)
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return int(datetime.datetime.strptime(value, fmt).timestamp())
        except ValueError:
            continue
    try:
        return int(datetime.datetime.fromisoformat(value).timestamp())
    except ValueError:
        return 0


def _to_int(value) -> int:
    if value in (None, '', ' '):
        return 0
    try:
        return int(str(value).strip())
    except ValueError:
        try:
            return int(float(str(value).strip()))
        except ValueError:
            return 0


def parse_nfdump_csv(lines: Iterator[str]) -> Iterator[Dict[str, int]]:
    """Yield flow-variable dicts from nfdump CSV lines (an iterable of strings).

    The header is inspected once to map each flow field onto whichever column
    name this nfdump build uses. Rows whose source address doesn't parse as IPv4
    (the trailing 'Summary'/stats block, or IPv6 flows) are skipped.
    """
    import csv
    reader = csv.DictReader(lines)
    header = set(reader.fieldnames or [])

    # Resolve canonical field -> actual column name present in this CSV.
    colmap: Dict[str, str] = {}
    for canon, candidates in _CSV_ALIASES.items():
        for name in candidates:
            if name in header:
                colmap[canon] = name
                break

    # Without source/destination address columns this isn't a flow CSV.
    if 'srcaddr' not in colmap or 'dstaddr' not in colmap:
        return

    int_fields = ('srcport', 'dstport', 'bytes', 'pkts', 'tos',
                  'input_if', 'output_if', 'src_as', 'dst_as')

    for row in reader:
        if row is None:
            continue
        srcaddr = _ip_to_int(row.get(colmap['srcaddr'], ''))
        dstaddr = _ip_to_int(row.get(colmap['dstaddr'], ''))
        if srcaddr is None or dstaddr is None:
            # Summary/stats line, IPv6, or malformed -> skip (don't stop; the
            # summary block can be preceded by a blank line).
            continue

        rec = {
            'srcaddr': srcaddr, 'dstaddr': dstaddr,
            'srcport': 0, 'dstport': 0, 'protocol': 0, 'bytes': 0, 'pkts': 0,
            'tos': 0, 'exporterip': 0, 'input_if': 0, 'output_if': 0,
            'src_as': 0, 'dst_as': 0, 'endtime': 0,
        }
        for canon in int_fields:
            if canon in colmap:
                rec[canon] = _to_int(row.get(colmap[canon]))

        if 'protocol' in colmap:
            pr = str(row.get(colmap['protocol'], '')).strip()
            if pr.isdigit():
                rec['protocol'] = int(pr)
            elif pr:
                try:
                    rec['protocol'] = normalize_proto(pr.lower())
                except OSError:
                    rec['protocol'] = 0

        if 'exporterip' in colmap:
            rec['exporterip'] = _ip_to_int(row.get(colmap['exporterip'], '')) or 0

        # endtime: prefer an explicit end column; else start (+ duration).
        if '_end' in colmap:
            rec['endtime'] = _parse_time(row.get(colmap['_end'], ''))
        elif '_start' in colmap:
            start = _parse_time(row.get(colmap['_start'], ''))
            dur = 0.0
            if '_dur' in colmap:
                try:
                    dur = float(row.get(colmap['_dur']) or 0)
                except ValueError:
                    dur = 0.0
            rec['endtime'] = int(start + dur)

        yield rec


#: nfcapd files are named nfcapd.YYYYMMDDHHMM, or nfcapd.YYYYMMDDHHMMSS when the
#: rotation interval is under 60s. (nfcapd.current.<pid> is the live file.)
_NFCAPD_RE = re.compile(r'nfcapd\.(\d{14}|\d{12})$')


def nfcapd_filetime(path: str) -> Optional[int]:
    """Capture time parsed from an nfcapd.<stamp> filename, or None if it doesn't
    match (e.g. nfcapd.current.<pid> or a non-nfcapd name)."""
    m = _NFCAPD_RE.search(os.path.basename(path))
    if not m:
        return None
    stamp = m.group(1)
    fmt = "%Y%m%d%H%M%S" if len(stamp) == 14 else "%Y%m%d%H%M"
    try:
        return int(datetime.datetime.strptime(stamp, fmt).timestamp())
    except ValueError:
        return None


def _mtime_or_now(path: str) -> int:
    try:
        return int(os.path.getmtime(path))
    except OSError:
        return int(time.time())


class NfdumpReader:
    """Reads nfcapd files by invoking the `nfdump` binary and parsing its CSV.

    Swap point: to support flow-tools instead, replace this class with one that
    yields the same dicts (e.g. from `flow-export -f2` / `ft2csv`). Nothing else
    in JKFlow.py needs to change.
    """

    def __init__(self, nfdump: str = 'nfdump', extra_args: Optional[List[str]] = None):
        self.nfdump = nfdump
        self.extra_args = extra_args or []

    def filetime_for(self, path: str) -> int:
        """Nominal capture time: from the nfcapd.<stamp> filename, else mtime."""
        ft = nfcapd_filetime(path)
        return ft if ft is not None else _mtime_or_now(path)

    def records(self, path: str) -> Iterator[Dict[str, int]]:
        cmd = [self.nfdump, '-r', path, '-q', '-o', 'csv'] + self.extra_args
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, bufsize=1)
        except FileNotFoundError:
            raise RuntimeError(
                f"Could not run '{self.nfdump}'. Install nfdump or pass --nfdump /path/to/nfdump."
            )
        try:
            yield from parse_nfdump_csv(proc.stdout)
        finally:
            if proc.stdout:
                proc.stdout.close()
            proc.wait()


class CsvFlowReader:
    """Reads flows from an nfdump-style CSV file already on disk (or '-' stdin).

    Useful when captures are pre-exported (`nfdump -r ... -o csv > flows.csv`),
    and for testing without the nfdump binary present.
    """

    def __init__(self, filetime: Optional[int] = None):
        self._filetime = filetime

    def filetime_for(self, path: str) -> int:
        # Explicit override wins; otherwise use the nfcapd timestamp in the name
        # (so sorting still works on nfcapd-named CSVs), falling back to mtime.
        if self._filetime is not None:
            return self._filetime
        ft = nfcapd_filetime(path)
        return ft if ft is not None else _mtime_or_now(path)

    def records(self, path: str) -> Iterator[Dict[str, int]]:
        import sys
        stream = sys.stdin if path == '-' else open(path, 'r')
        try:
            yield from parse_nfdump_csv(stream)
        finally:
            if stream is not sys.stdin:
                stream.close()


def process_file(jk: 'JKFlow', reader, path: str) -> int:
    """Run one flow file through the engine: reset, feed every record, report."""
    jk.filetime = reader.filetime_for(path)
    jk.perfile()
    fv = Cflow.flowvars           # mutate in place; never reassign
    n = 0
    for rec in reader.records(path):
        fv.update(rec)
        jk.wanted()
        n += 1
    jk.report()
    return n


def move_processed(path: str, processed_dir: str) -> Optional[str]:
    """Move a processed flow file into processed_dir.

    A relative processed_dir (e.g. 'processed') is taken relative to the file's
    own directory; an absolute path is used as-is. Returns the new path, or None
    if the move was skipped/failed.
    """
    import shutil
    base = os.path.basename(path)
    if os.path.isabs(processed_dir):
        target_dir = processed_dir
    else:
        target_dir = os.path.join(os.path.dirname(os.path.abspath(path)), processed_dir)
    try:
        os.makedirs(target_dir, exist_ok=True)
        dest = os.path.join(target_dir, base)
        shutil.move(path, dest)
        return dest
    except OSError as e:
        logging.warning(f"Could not move {path} to {target_dir}: {e}")
        return None


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="JKFlow - XML-configurable NetFlow reporting (nfdump/nfcapd)."
    )
    ap.add_argument('files', nargs='+',
                    help="nfcapd files (or nfdump CSV files with --csv, '-' for stdin)")
    ap.add_argument('-c', '--config', default=None,
                    help="Path to JKFlow.xml (default: $JKFLOW_XML or /usr/local/bin/JKFlow.xml)")
    ap.add_argument('--rrddir', default=None, help="Override <rrddir> from the config")
    ap.add_argument('--scoredir', default=None, help="Override <scoredir> from the config")
    ap.add_argument('--nfdump', default='nfdump', help="Path to the nfdump binary")
    ap.add_argument('--csv', action='store_true',
                    help="Treat inputs as nfdump CSV files instead of nfcapd binaries")
    ap.add_argument('--processed-dir', default=None, metavar='DIR',
                    help="After processing, move each flow file here. Relative names "
                         "(e.g. 'processed') are relative to the file's own directory; "
                         "absolute paths are used as-is. The live nfcapd.current.* file "
                         "is never moved.")
    ap.add_argument('--rrd-start', default=None, metavar='EPOCH|first',
                    help="Anchor the start time of NEWLY created RRDs, so historical "
                         "captures can be back-filled (rrdtool otherwise starts new "
                         "RRDs at 'now' and rejects older data). Give an epoch second, "
                         "or 'first' to auto-detect one step before the earliest input "
                         "file. Only affects RRDs that don't exist yet.")
    ap.add_argument('--no-sort', action='store_true',
                    help="Process files in the given order instead of sorting by "
                         "capture time (sorting is the default and keeps RRD updates "
                         "monotonic).")
    ap.add_argument('--include-current', action='store_true',
                    help="Also process the live nfcapd.current.* file (skipped by "
                         "default because it is still being written).")
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s: %(message)s")

    jk = JKFlow(config_path=args.config)
    if args.rrddir:
        jk.RRDDIR = args.rrddir
    if args.scoredir:
        jk.SCOREDIR = args.scoredir

    reader = CsvFlowReader() if args.csv else NfdumpReader(nfdump=args.nfdump)

    # Process strictly in chronological order. RRD requires monotonically
    # increasing update timestamps, so out-of-order files (e.g. from an unsorted
    # shell glob, mixed 12-/14-digit names, or the lexically-last nfcapd.current)
    # would trigger "illegal attempt to update using time ... when last update
    # time is ...". Sorting by the derived capture time makes it order-independent.
    files = list(args.files)
    if not args.no_sort:
        files.sort(key=reader.filetime_for)

    # Back-fill anchor for newly created RRDs.
    if args.rrd_start is not None:
        if str(args.rrd_start).lower() == 'first':
            candidates = [reader.filetime_for(p) for p in files
                          if 'current' not in os.path.basename(p)]
            if candidates:
                jk.rrd_start = min(candidates) - jk.SAMPLETIME
        else:
            try:
                jk.rrd_start = int(args.rrd_start)
            except ValueError:
                ap.error(f"--rrd-start must be an epoch integer or 'first', got {args.rrd_start!r}")
        if jk.rrd_start is not None:
            when = datetime.datetime.fromtimestamp(jk.rrd_start)
            print(f"Anchoring new RRDs at {jk.rrd_start} ({when}); "
                  f"existing RRDs are left as-is.")

    total = 0
    for path in files:
        base = os.path.basename(path)
        # The live capture file is still being written -> incomplete and its
        # timestamp is only an mtime; skip it unless asked to include it.
        if 'current' in base and not args.include_current:
            print(f"Skipping live capture file {path} (use --include-current to process it)")
            continue
        n = process_file(jk, reader, path)
        total += n
        print(f"Processed {n} flows from {path} (filetime={jk.filetime})")
        # Move the file aside only after it was processed without raising.
        if args.processed_dir and 'current' not in base:
            dest = move_processed(path, args.processed_dir)
            if dest:
                print(f"  -> moved to {dest}")
    print(f"Done. {total} flows across {len(files)} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
