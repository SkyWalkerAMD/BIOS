"""Execute captured guard bytes, not a recompiled policy, with explicit HII models."""
from pathlib import Path
import hashlib,json,sys,types,struct
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent
REV=HERE/'trace_revisions'/sys.argv[1]
meta=json.loads((REV/'build/split_build.json').read_text())
module=types.ModuleType('verify_split');module.__file__=str(D04/'diagnostic_guard09/verify_split.py')
exec(compile((REV/'verify_split.py').read_text(),str(REV/'verify_split.py'),'exec'),module.__dict__)
module.BUILD=REV/'build';module.meta=meta;sys.modules['verify_split']=module
chrome=D04/'static_chrome_candidate07/verify_chrome.py'
prefix=chrome.read_text().split('\nchecks=[];observations=[]',1)[0]
ns={'__file__':str(chrome)};exec(compile(prefix,str(chrome)+' [snapshot guard model only]','exec'),ns)
V,S,q,d,w,TSE,HEAP=[ns[x]for x in ['ChromeVM','S','q','d','w','TSE','HEAP']]
base_ns=ns['ns'];STATE=base_ns['SPLIT_STATE_ADDRESS']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

class TraceVM(V):
 def __init__(self,case):
  self.captured=[];super().__init__(4)
  self.u.mem_write(STATE+0x40,q(0x3930474149444753)+d(1)+d(576)+bytes(560))
  self.u.mem_write(self.page+0x20,q(0x99998888))
  self.provider_present=True;self.provider_bits=3
  if case=='two_control_stale_ifr':
   arr=HEAP+0x272000;c0=arr+0x100;c1=arr+0x200;ifr=arr+0x300
   self.u.mem_write(self.frame+0x20,d(0));self.u.mem_write(self.frame+0x3c,d(2));self.u.mem_write(self.frame+0x48,q(arr))
   self.u.mem_write(arr,q(c0)+q(c1));self.u.mem_write(c0+0x20,q(self.handle));self.u.mem_write(c0+0x48,q(ifr))
   self.u.mem_write(ifr,bytes.fromhex('0591000000003412010000000010000100'))
   self.u.mem_write(c1+0x20,q(0xdead1111))
 def hook(self,u,a,n,data):
  if a==base_ns['REQUEST']:
   raw=bytes(u.mem_read(STATE+0x180,256));valid=struct.unpack_from('<Q',raw,16)[0]
   self.captured.append({'hook':struct.unpack_from('<I',raw,0)[0],'reason':struct.unpack_from('<I',raw,4)[0],
    'classification':struct.unpack_from('<i',raw,8)[0],'valid':hex(valid),'control_index':struct.unpack_from('<I',raw,96)[0],
    'owner_detail':hex(struct.unpack_from('<I',raw,60)[0]),'frame_kind':struct.unpack_from('<I',raw,84)[0],
    'control_vtable_rva':hex(struct.unpack_from('<I',raw,100)[0]),'opcode':struct.unpack_from('<I',raw,128)[0],
    'opcode_length':struct.unpack_from('<I',raw,132)[0],'varstore':struct.unpack_from('<I',raw,136)[0],
    'ifr_valid':bool(valid&(1<<8)),'control_type_valid':bool(valid&(1<<16)),
    'control_vtable_valid':bool(valid&(1<<17)),'raw_record_hex':raw.hex()})
  super().hook(u,a,n,data)

rows=[]
for case in ['kind4_primary_owner','two_control_stale_ifr']:
 vm=TraceVM(case);vm.call(S['AMITSE']['gate_poll'])
 assert vm.provider_calls['request']==1 and len(vm.captured)==1
 record=vm.captured[0];assert record['hook']==5 and record['reason']==11 and record['classification']==-1
 assert record['owner_detail'].startswith('0x2')
 if case=='kind4_primary_owner':
  assert record['frame_kind']==4 and record['control_vtable_rva']=='0x6d6f0' and record['control_vtable_valid']
  assert not record['ifr_valid'] and not record['control_type_valid']
 else:assert record['control_index']==1
 rows.append({'case':case,'request_calls':vm.provider_calls['request'],'manage_calls':vm.provider_calls['manage'],'original_poll_calls':vm.calls['poll'],'record':record})
stale=rows[1]['record']['ifr_valid']
report={'status':'CONFIRMED_STALE_PREVIOUS_CONTROL_IFR_DIAGNOSTIC'if stale else'PASS_PER_CONTROL_TRACE_ISOLATION',
 'template_sha256':meta['template_sha256'],'source_snapshot_binding':json.loads((REV/'snapshot.json').read_text())['source_binding_matches'],
 'script_sha256':sha(Path(__file__)),'rows':rows,'stale_fields_observed':stale,
 'scope':['Actual captured guard instructions and original frame constructor execute. HII/ConfigAccess/provider services, gate_memory and original poll are explicit models.','Kind4 reason is captured before Request: D09_CONTROL_OWNER, kind4, vtable6D6F0, owner domain2, unread IFR/type invalid.','The two-control case has a safe Setup question first and unknown-owner second. A valid IFR on the second record is stale attribution, not a policy grant.','A source snapshot may be newer than the captured executable while author development proceeds; per-file mismatch is disclosed. Only the binary/fixture metadata are the actual executed identity.','No physical access, new guard policy, variable write, native field mutation on hardware, or full native browser execution.']}
out=REV/'control_trace_result.json';assert not out.exists(),'Preserve prior result; new script/revision needed.'
out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'result_sha256':sha(out)}))
