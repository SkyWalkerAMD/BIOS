"""Actual candidate PE, private loop wrapper and registered notify callback.

UEFI, page objects and scheduling are explicit fixtures. Test-only C callers
exercise the real ticket API through their generated instruction windows.
"""
from pathlib import Path
import hashlib,json,re,struct,sys,time
H=Path(__file__).resolve().parent;B=H.parents[1];R=B.parents[2]
sys.path.insert(0,str(B/'navigation05'))
import verify_navigation as n
from verify_navigation import m,ns,TSE,DATA,Q,I
import pefile
from unicorn.x86_const import *
O=H/'build';DLL=O/'W890ObserverGeneration08r3.TESTONLY.dll'
m.OP.close();m.OP=pefile.PE(str(DLL));m.OB=m.OP.OPTIONAL_HEADER.ImageBase
m.OS={e.name.decode():m.OB+e.address for e in m.OP.DIRECTORY_ENTRY_EXPORT.symbols}
m.SY={k:int(v,16) for k,v in re.findall(r'^\s*\w+:\w+\s+(\w+)\s+([0-9A-Fa-f]{16})\s',(O/'navigation.map').read_text(),re.M)}
n.OS=m.OS;n.SY=m.SY;ns['SYMBOLS']=m.SY;OS=m.OS;SY=m.SY
n.CALLS=json.loads((O/'consumer_windows.json').read_text())

class VM(n.VM):
 def __init__(self):
  super().__init__();self.labmode=None;self.lab_calls=0;self.chain=[]
  self.chain_return=ns['HOOK']+0x6e00;self.w(self.chain_return,b'\xc3')
  self.chain_sp=None;self.result=DATA+0x33000
 def start_next(self):
  if not self.chain:
   self.u.reg_write(UC_X86_REG_RSP,self.chain_sp);self.chain_sp=None;self.ret(ns['ERR'](14));return
  fn,args=self.chain.pop(0);sp=self.chain_sp-0x100
  self.w(sp,bytes(0x80));self.w(sp,Q(self.chain_return));self.u.reg_write(UC_X86_REG_RSP,sp)
  for i,r in enumerate(ns['REGS']):self.u.reg_write(r,args[i] if i<len(args) else 0)
  for i in range(4,len(args)):self.w(sp+40+(i-4)*8,Q(args[i]))
  self.u.reg_write(UC_X86_REG_RIP,fn)
 def hook(self,u,address,size,opaque):
  if hasattr(self,'chain_return'):
   if address==self.chain_return:self.start_next();return
   if address==self.hooks['get'] and self.r(self.arg(0),32)=='Generation08Lab\0'.encode('utf-16-le'):
    self.lab_calls+=1
    if self.labmode is None:self.ret(ns['ERR'](14));return
    mode=self.labmode;self.labmode=None;self.chain_sp=u.reg_read(UC_X86_REG_RSP)
    if mode=='foreign':self.chain=[(self.notify_callback,[2,0,0,0x920000,2])]
    elif mode=='strings':self.chain=[(self.notify_callback,[4,0,0,0x920000,2])]
    elif mode=='nested_only':self.chain=[]
    else:raise AssertionError(mode)
    self.chain.append((OS['og08_test_nested'],[]));self.start_next();return
  return super().hook(u,address,size,opaque)
 def result_fields(self):
  a=struct.unpack('<QQQIIIII',self.r(self.result,44))
  return dict(zip(('before_generation','after_generation','read_status','entered','before_valid','after_valid','nested_entered','nested_old_valid'),a))

def main():
 cases=[]
 def case(name,body):
  start=time.monotonic();v=VM();v.ready();details=body(v)
  assert not v.set_count,'No test should write a credential even in the model'
  cases.append({'name':name,'passed':True,'seconds':round(time.monotonic()-start,3),'details':details})
  print(name,flush=True)
 def generation(v):
  g=DATA+0x34000;v.loop([('no_catalog_generation',[g]),lambda w:assert_q(w,g,1),
   (v.notify_callback,[2,0,0,0x920000,1]),('no_catalog_generation',[g]),lambda w:assert_q(w,g,2),
   (v.notify_callback,[2,0,0,0x920000,2]),('no_catalog_generation',[g]),lambda w:assert_q(w,g,3),
   (v.notify_callback,[2,0,0,0x920000,8]),('no_catalog_generation',[g]),lambda w:assert_q(w,g,4),
   ('n05_check',[2,v.page_list[1],0]),('no_identity',[v.idbuf])])
  assert v.sequence_values[-2:]==[0,1]
  return {'generations':[1,2,3,4],'safe_main_still_valid':True}
 def assert_q(v,p,wanted):assert v.q(p)==wanted,(v.q(p),wanted)
 case('Three foreign FORMS event kinds retain the private BIOS visit',generation)
 def locked(v):
  v.queue('\x1b');v.loop([(v.notify_callback,[2,0,0,0x920000,2]),('n05_check',[2,v.page_list[2],0])])
  assert v.sequence_values[-1]==ns['ERR'](15) and v.index()==2
  return {'denied_protected_page':True,'settings_writes':0}
 case('Foreign refresh grants no Ai Tweaker authorization',locked)
 def query_outside(v):
  g=DATA+0x34000;v.w(g,Q(0x1111));assert v.run('no_catalog_generation',g)==0 and v.q(g)==0x1111
  return {'outside_private_loop_denied':True}
 case('Catalog stamp cannot manufacture a private native visit',query_outside)
 def read(v,mode):
  v.labmode=mode;v.w(v.result,bytes(64));v.loop([('og08_test_read',[v.app,v.result])])
  a=v.result_fields();assert v.sequence_values==[1] and a['entered']==a['before_valid']==1
  assert a['nested_entered']==0
  if mode=='foreign':assert a['after_generation']==a['before_generation']+1 and a['after_valid']==a['nested_old_valid']==0 and a['read_status']==ns['ERR'](15)
  else:assert a['after_generation']==a['before_generation'] and a['after_valid']==a['nested_old_valid']==1 and a['read_status']==ns['ERR'](14)
  return a
 case('Foreign notification invalidates held ticket and rejects same-slot reentry',lambda v:read(v,'foreign'))
 case('Nested entry cannot reuse an occupied valid ticket',lambda v:read(v,'nested_only'))
 case('String-only update leaves the FORMS generation unchanged',lambda v:read(v,'strings'))
 def renew(v):
  v.labmode='foreign';records=[]
  def save(w):records.append(w.result_fields());w.w(w.result,bytes(64))
  v.loop([('og08_test_read',[v.app,v.result]),save,('og08_test_read',[v.app,v.result]),save])
  assert v.sequence_values==[1,1] and records[0]['after_valid']==0 and records[1]['after_valid']==1
  assert records[1]['before_generation']==records[0]['after_generation']
  return {'previous_scope':records[0],'new_scope':records[1]}
 case('Original owner leave permits a new proof in the same BIOS visit',renew)
 def setup(v,handle=None):
  h=v.setup_hii if handle is None else handle
  v.loop([(v.notify_callback,[2,0,0,h,2]),('n05_check',[2,v.page_list[1],0])])
  assert v.sequence_values[-1]==ns['ERR'](15)
  assert v.run('no_identity',v.idbuf)==1
  # NO_IDENTITY ends in epoch(u64),loop_depth,send_depth,fault,ended.
  assert int.from_bytes(v.r(v.idbuf+96,4),'little')==1
  return {'unknown_setup_or_null_notify_revokes':True}
 case('Unapproved Setup change still revokes identity',setup)
 case('Malformed null HII notification never becomes an ordinary foreign update',lambda v:setup(v,0))
 report={'passed':True,'checks':len(cases),'component_sha256':hashlib.sha256(DLL.read_bytes()).hexdigest(),
  'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'cases':cases,
  'test_consumer_only':True,'models':['UEFI services and callback scheduling; synthetic pages and allocations.',
   'Private actual loop wrapper executes; BrowserLoop body is a sequence fixture.',
   'SHA/PBKDF/RDSEED use pre-existing independent test oracles.',
   'No BMC operation, actual password change, native HII rebuild or full GUI qualification.']}
 (H/'generation_tests.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(cases))
if __name__=='__main__':main()
