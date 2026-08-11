import os, ipaddress, json
os.environ['JKFLOW_XML'] = '/tmp/JKFlow.xml'
import JKFlow
from JKFlow import JKFlow as JK, Cflow, parse_nfdump_csv, NfdumpReader

def ip(s): return int(ipaddress.ip_address(s))

print("=== 1. Construct + parse config (nfdump path assumed) ===")
jk = JK(config_path='/tmp/JKFlow.xml')
assert 'all' in jk.mylist, "all direction missing"
assert 'dmz' in jk.mylist['direction'], "dmz direction missing"
print("  config parsed: all + direction 'dmz' present")
print("  all.service protocols:", list(jk.mylist['all'].get('service', {}).keys()))
print("  all.protocol keys   :", list(jk.mylist['all'].get('protocol', {}).keys()))

print("\n=== 2. Feed synthetic flows through wanted() ===")
def feed(**kw):
    base = dict(srcaddr=0,dstaddr=0,srcport=0,dstport=0,protocol=0,bytes=0,
                pkts=0,tos=0,exporterip=0,input_if=1,output_if=2,src_as=0,
                dst_as=0,endtime=1700000000)
    base.update(kw); Cflow.flowvars.update(base); jk.wanted()

# outbound web hit: local 10.5.0.1 -> external 8.8.8.8 :443
feed(srcaddr=ip("10.5.0.1"), dstaddr=ip("8.8.8.8"), srcport=51000, dstport=443,
     protocol=6, bytes=1500, pkts=3)
# inbound web hit: external -> local, src port 80
feed(srcaddr=ip("8.8.8.8"), dstaddr=ip("10.5.0.1"), srcport=80, dstport=51001,
     protocol=6, bytes=800, pkts=2)
# dns udp/53 outbound
feed(srcaddr=ip("10.5.0.2"), dstaddr=ip("1.1.1.1"), srcport=40000, dstport=53,
     protocol=17, bytes=200, pkts=1)
# dmz direction: 10.1.0.5 -> 10.2.0.9 ssh/22
feed(srcaddr=ip("10.1.0.5"), dstaddr=ip("10.2.0.9"), srcport=50000, dstport=22,
     protocol=6, bytes=5000, pkts=10)

allt = jk.mylist['all']['total']
print("  all.total:", json.dumps(allt))
assert allt['out']['flows'] >= 2, "expected outbound flows in all.total"
assert allt['in']['flows'] >= 1, "expected inbound flow in all.total"

# service 443/tcp should have registered under all.service[6][443]
svc443 = jk.mylist['all']['service'][6][443]
print("  all.service tcp/443:", json.dumps(svc443))
assert svc443.get('dst',{}).get('out',{}).get('flows',0) == 1, "443 dst/out not counted"

# dmz direction total should have the ssh flow
dmz = jk.mylist['direction']['dmz']['total']
print("  dmz.total:", json.dumps(dmz))
assert (dmz.get('out',{}).get('flows',0) + dmz.get('in',{}).get('flows',0)) >= 1, "dmz not counted"
print("  OK: counters moved correctly")

print("\n=== 3. nfdump CSV parser ===")
csv_text = """ts,te,td,sa,da,sp,dp,pr,flg,fwd,stos,ipkt,ibyt,opkt,obyt,in,out,sas,das,smk,dmk,dtos,dir,nh,nhb,svln,dvln,ismc,odmc,idmc,osmc,ra,eng,exid,tr
2023-11-14 22:13:20.000,2023-11-14 22:13:21.000,1.000,10.5.0.1,8.8.8.8,51000,443,TCP,....,0,0,3,1500,0,0,1,2,64500,15169,24,32,0,0,0.0.0.0,0.0.0.0,0,0,0,0,0,0,192.168.1.1,0,0,0
2023-11-14 22:13:22.000,2023-11-14 22:13:23.000,1.000,8.8.8.8,10.5.0.1,80,51001,TCP,....,0,0,2,800,0,0,2,1,15169,64500,32,24,0,0,0.0.0.0,0.0.0.0,0,0,0,0,0,0,192.168.1.1,0,0,0
Summary
flows,bytes,packets,avg_bps,avg_pps,avg_bpp
2,2300,5,0,0,0
"""
recs = list(parse_nfdump_csv(iter(csv_text.splitlines())))
print("  parsed records:", len(recs))
for r in recs: print("   ", {k:r[k] for k in ('srcaddr','dstaddr','srcport','dstport','protocol','bytes','pkts','exporterip','src_as','dst_as')})
assert len(recs) == 2, "should parse exactly 2 flows (summary skipped)"
assert recs[0]['protocol'] == 6, "TCP should map to 6"
assert recs[0]['bytes'] == 1500 and recs[0]['pkts'] == 3
assert recs[0]['exporterip'] == ip("192.168.1.1"), "exporter (ra) not parsed"
assert recs[0]['dst_as'] == 15169 and recs[0]['src_as'] == 64500
print("  OK: CSV mapped by column name, summary block skipped")

print("\n=== 4. filetime_for from nfcapd filename ===")
ft = NfdumpReader().filetime_for("/var/flows/nfcapd.202311142210")
import datetime as dt
print("  nfcapd.202311142210 ->", dt.datetime.fromtimestamp(ft))
assert ft > 0

print("\nALL TESTS PASSED")
