"""Enabled observation, exact guard instructions and policy differential.

The original frame constructors execute. Firmware ownership/services, provider,
memory visibility and final OEM body are explicit fixtures, not hardware proof.
"""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys, zlib
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

def namespace(core):
 spec=importlib.util.spec_from_file_location('verify_split',core/'verify_split.py')
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 sys.modules['verify_split']=module
 prefix=(core/'verify_chrome.py').read_text().split('\nchecks=[];observations=[]',1)[0]
 scope={'__file__':str(core/'verify_chrome.py')}
 exec(compile(prefix,str(core/'verify_chrome.py')+' [definitions only]','exec'),scope)
 return scope

def record(raw):
 u32=lambda o:struct.unpack_from('<I',raw,o)[0]
 s32=lambda o:struct.unpack_from('<i',raw,o)[0]
 u64=lambda o:struct.unpack_from('<Q',raw,o)[0]
 zeroed=bytearray(raw);zeroed[232:236]=bytes(4)
 return dict(hook=u32(0),reason=u32(4),classification=s32(8),detail=u32(12),valid=u64(16),
  stage=u64(24),page_index=u32(40),form_id=u32(44),page_owner=s32(56),owner_reason=u32(60),
  owner_status=u64(64),frame_index=u32(80),frame_kind=u32(84),frame_count=u32(88),
  control_index=u32(96),control_vtable=u32(100),control_type=u32(104),control_owner=s32(120),
  hii_class=u32(124),opcode=u32(128),length=u32(132),store=u32(136),serial=u64(240),
  crc_ok=u32(232)==zlib.crc32(zeroed),raw_sha256=hashlib.sha256(raw).hexdigest())

def vm_type(scope,enabled):
 V=scope['ChromeVM'];ns=scope['ns'];U=scope['U'];STATE=ns['SPLIT_STATE_ADDRESS']
 q,d,w=scope['q'],scope['d'],scope['w'];TSE,HEAP=scope['TSE'],scope['HEAP']
 class TraceVM(V):
  def __init__(self,kind=4):
   self.observing=False;self.events=[];self.requests=[];self.writes=[]
   super().__init__(kind)
   if enabled:self.u.mem_write(STATE+0x40,q(0x3930474149444753)+d(1)+d(576)+bytes(560))
   self.u.mem_write(self.page+0x20,q(0x99998888))
   self.provider_present=True;self.provider_bits=3
   self.u.mem_write(TSE+0x83468,q(5))
   self.u.hook_add(U.UC_HOOK_MEM_WRITE,self.write_hook)
  def write_hook(self,u,access,address,size,value,data):
   if self.observing:self.writes.append((address,size,value&((1<<(size*8))-1)))
  def hook(self,u,a,n,data):
   if self.observing:
    if a==ns['LOC']:self.events.append(('locate',bytes(u.mem_read(self.arg(0),16)).hex()))
    elif a==ns['HANDLE']:self.events.append(('handle',self.arg(0),bytes(u.mem_read(self.arg(1),16)).hex()))
    elif a==ns['GETDRIVER']:self.events.append(('get_driver',self.arg(1)))
    elif a==ns['LIST']:self.events.append(('list',))
    elif a in [ns[x]for x in ['QUERY','REQUEST','MANAGE']]:
     self.events.append((next(x.lower()for x in ['QUERY','REQUEST','MANAGE']if ns[x]==a),))
    if a==ns['REQUEST'] and enabled:
     self.requests.append(record(bytes(u.mem_read(STATE+0x180,256))))
   super().hook(u,a,n,data)
  def run(self,hook='gate_poll',*args):
   self.observing=True
   module='Setup'if hook=='gate_callback'else'AMITSE'
   result=self.call(scope['S'][module][hook],*args)
   self.observing=False
   return result
  def first(self):return record(bytes(self.u.mem_read(STATE+0x80,256)))
  def unknown_two_controls(self,protected=False):
   arr=HEAP+0x272000;c0=arr+0x100;c1=arr+0x200;ifr=arr+0x300
   self.u.mem_write(self.frame+0x20,d(0));self.u.mem_write(self.frame+0x3c,d(2));self.u.mem_write(self.frame+0x48,q(arr))
   self.u.mem_write(arr,q(c0)+q(c1));self.u.mem_write(c0+0x20,q(self.handle));self.u.mem_write(c0+0x48,q(ifr))
   data=bytearray.fromhex('0591000000003412010000000010000100')
   if protected:data[8:10]=w(29)
   self.u.mem_write(ifr,bytes(data));self.u.mem_write(c1+0x20,q(0xdead1111))
 return TraceVM

new=namespace(HERE);old=namespace(D04/'static_chrome_candidate07')
N=vm_type(new,True);O=vm_type(old,False)
q,d,w,TSE,HEAP=[new[x]for x in ['q','d','w','TSE','HEAP']]
STATE=new['ns']['SPLIT_STATE_ADDRESS'];STACK=new['ns']['STACK']
checks=[];rows=[]
def check(name,condition):assert condition,name;checks.append(name)

def configure(v,case):
 if case=='two_control':v.unknown_two_controls()
 elif case=='question':v.unknown_two_controls(True)
 elif case=='form_index':v.u.mem_write(v.page+0x30,w(0xffff))
 elif case=='page_owner':v.u.mem_write(v.page+0x20,q(0))
 elif case=='protected_form':
  v.u.mem_write(v.page+0x20,q(v.handle));v.u.mem_write(v.records+10,w(0x2714))
 elif case=='chrome_callback':v.u.mem_write(v.control+8,q(TSE+0x11164))
 elif case=='grant':v.provider_bits=7
 elif case=='accept':v.request_accept=True
 elif case=='no_owner':v.provider_bits=1
 elif case=='missing_provider':v.provider_present=False

for case in ['kind4','two_control','question','form_index','page_owner','protected_form','chrome_callback','grant','accept','no_owner','missing_provider']:
 kind=1 if case=='chrome_callback' else 4
 a,b=N(kind),O(kind)
 for v in [a,b]:configure(v,case)
 # The reference page is explicitly foreign, not inferred from its test label.
 if case not in ['page_owner','protected_form']:
  check(case+' page fixture explicitly foreign',a.call(new['S']['AMITSE']['gate_owner'],0x99998888,0)==0)
 ra,rb=a.run(),b.run()
 check(case+' same authorization/output endpoints',a.calls==b.calls and a.provider_calls==b.provider_calls and a.provider_bits==b.provider_bits)
 check(case+' identical HII/provider call order and arguments',a.events==b.events)
 check(case+' no variable/allocation calls',not a.getvar_calls and not a.alloc_calls)
 # Ignore the native stack and the one owned diagnostic extent. OEM writes
 # remain byte-for-byte identical, including legitimate redirect side effects.
 filtered=lambda v:[x for x in v.writes if not(STACK<=x[0]<STACK+0x400000)and not(STATE+0x40<=x[0]and x[0]+x[1]<=STATE+0x280)]
 check(case+' no additional non-stack/non-diagnostic writes',filtered(a)==filtered(b))
 state_writes=[x for x in a.writes if STATE<=x[0]<STATE+4096]
 check(case+' diagnostic writes within owned 576 bytes',all(STATE+0x40<=x[0]and x[0]+x[1]<=STATE+0x280 for x in state_writes))
 if a.requests:
  r=a.requests[-1];check(case+' current record CRC and serial valid',r['crc_ok']and r['serial']==1)
  check(case+' first record frozen with zero serial',a.first()['crc_ok']and a.first()['serial']==0)
  if case=='kind4':
   check('actual kind4 ctor source failure precise',r['hook']==5 and r['reason']==11 and r['detail']==0x02000003 and r['control_vtable']==0x6d6f0 and r['frame_kind']==4)
   check('kind4 unread IFR and type absent',not(r['valid']&((1<<8)|(1<<16))))
  if case=='two_control':
   check('second control owns failure record',r['control_index']==1 and r['reason']==11 and r['detail']==0x02000002)
   check('second control has no first-control IFR attribution',not(r['valid']&(1<<8))and r['opcode']==0 and r['length']==0 and r['store']==0)
  if case=='question':check('protected question retained',r['reason']==15 and r['classification']==1 and r['store']==29 and r['control_index']==0)
  if case=='form_index':check('bad page index exact cause',r['reason']==4 and r['detail']==1 and not(r['valid']&(1<<5)))
  if case=='page_owner':check('page ownership domain distinct',r['reason']==6 and r['detail']==0x01000004)
  if case=='protected_form':check('protected form retained',r['reason']==14 and r['classification']==1 and r['form_id']==0x2714)
  if case=='chrome_callback':check('strict chrome failure retained',r['reason']==19 and r['classification']==-1)
 rows.append(dict(case=case,requests=a.requests,first=a.first()if a.getq(STATE+0x50)else None,provider_calls=a.provider_calls,OEM_calls=a.calls))

a=N();a.run('gate_render',a.page);first=bytes(a.u.mem_read(STATE+0x80,256))
check('render denial stores first without prompting',a.first()['hook']==1 and not a.requests)
a.u.mem_write(a.page+0x30,w(0xffff));a.run()
check('later poll current cause differs while first survives redirect scans',bytes(a.u.mem_read(STATE+0x80,256))==first and a.requests[-1]['hook']==5 and a.requests[-1]['reason']==4)
a.run();check('a new Request receives increasing serial',a.requests[-1]['serial']==2)
check('returned request no longer pending',not(int.from_bytes(a.u.mem_read(STATE+0x7c,4),'little')&4))

for label,mutate in [
 ('missing magic',lambda v:v.u.mem_write(STATE+0x40,q(0))),
 ('wrong revision',lambda v:v.u.mem_write(STATE+0x48,d(2))),
 ('wrong bytes',lambda v:v.u.mem_write(STATE+0x4c,d(575))),
 ('unknown flags',lambda v:v.u.mem_write(STATE+0x7c,d(0x80000000))),
 ('unwritable region',lambda v:v.memory_deny.append((STATE+0x40,STATE+0x280,1))),
 ('unreadable region',lambda v:v.memory_deny.append((STATE+0x40,STATE+0x280,0))),
 ('writer busy',lambda v:v.u.mem_write(STATE+0x78,d(1))),
 ('request overflow',lambda v:v.u.mem_write(STATE+0x60,q(0xffffffffffffffff))),
 ('torn request',lambda v:v.u.mem_write(STATE+0x58,q(1)))]:
 a=N();mutate(a);a.run()
 check(label+' observation cannot grant or stop original denial',a.provider_calls['request']==1 and not a.calls['poll'] and a.provider_bits==3)
 check(label+' state prefix and tail unchanged',bytes(a.u.mem_read(STATE,32))[16:24]==q(0x3331535441544547)and not any(a.u.mem_read(STATE+0x280,4096-0x280)))

# Real local navigation and callback gates, with the same modeled owner.
a=N();a.observing=True;a.nav(0x2714);a.observing=False
check('navigation request origin preserved',a.requests[-1]['hook']==6 and a.requests[-1]['reason']==30)
a=N();a.run('gate_defaults',0xffff001d,0,0,0)
check('defaults request origin preserved',a.requests[-1]['hook']==7 and a.requests[-1]['reason']==29)
a=N(1);key=HEAP+0x274000
a.u.mem_write(a.app+0x28,d(1)+d(2));a.u.mem_write(a.array,q(a.page)+q(a.page))
a.u.mem_write(key+8,w(1));a.u.mem_write(key+12,w(0x0f))
a.run('gate_app_input',a.app,key)
check('F5 request on otherwise safe page preserves its distinct origin',a.requests[-1]['hook']==3 and a.requests[-1]['reason']==28 and a.requests[-1]['classification']==1)
a=N();a.observing=True;a.callback(0x5a);a.observing=False
if not a.requests:
 # Derive one known protected ID from the exact generated policy table.
 import re
 table=(HERE/'source/policy_data.h').read_text().split('protected_questions[]',1)[1].split('};',1)[0]
 protected=int(re.findall(r'0x[0-9a-fA-F]+',table)[0],16)
 a=N();a.observing=True;a.callback(protected);a.observing=False
check('Setup callback request origin preserved',a.requests[-1]['hook']==8 and a.requests[-1]['reason']==31)

report=dict(status='PASS_ENABLED_DIAGNOSTICS_AND_FROZEN07_POLICY_DIFFERENTIAL',checks=len(checks),check_names=checks,
 template_sha256=json.loads((HERE/'build/split_build.json').read_text())['template_sha256'],
 template_source_sha256=sha(HERE/'source/gate.c'),test_source_sha256=sha(Path(__file__)),
 reference_template_sha256=sha(D04/'static_chrome_candidate07/build/guard_template.bin'),rows=rows,
 limits=['Exact guard instructions and selected original frame constructor instructions execute in Unicorn.',
 'HII ownership, provider, permission responses, native final bodies, and general services are explicit models.',
 'No actual provider password UI is part of this test. No hardware invocation or real NVRAM write.',
 'The kind4 counterexample is not an observed hardware execution trace or proof of physical root cause.',
 'No safe-page classification, ownership rule or exit behavior is relaxed. Unknown remains denied.'])
(HERE/'build/diagnostic_verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'checks':len(checks),'sha256':sha(HERE/'build/diagnostic_verification.json')}))
