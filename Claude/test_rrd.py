import os, tempfile
os.environ['JKFLOW_XML']='/tmp/JKFlow.xml'
import JKFlow

calls={'create':[],'update':[]}
class FakeRRD:
    def create(self,*a): calls['create'].append(a)
    def update(self,*a): calls['update'].append(a)
JKFlow.rrdtool=FakeRRD()   # inject

from JKFlow import JKFlow as JK, CsvFlowReader, process_file
d=tempfile.mkdtemp()
jk=JK(config_path='/tmp/JKFlow.xml'); jk.RRDDIR=d; jk.SCOREDIR=d
n=process_file(jk, CsvFlowReader(filetime=1699999999), '/tmp/flows.csv')
print("flows:",n,"| rrd creates:",len(calls['create']),"| rrd updates:",len(calls['update']))
print("\nsample create args:", calls['create'][0])
print("sample update args:", calls['update'][0])
# validate update format: 'timestamp:v1:v2:...'
ts_line=calls['update'][0][1]
parts=ts_line.split(':')
assert parts[0]=='1699999999', ts_line
assert len(parts)==7, f"expected timestamp + 6 DS values, got {len(parts)}"
print("\nupdate payload well-formed: timestamp + 6 values (in/out x bytes/pkts/flows)")
print("ALL RRD-PATH CHECKS PASSED")
