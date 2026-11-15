"""Focused actual-byte navigation regression after lifecycle narrowing.

Uses immutable original-parser raw data; outer GUI and standard EFI remain
declared fixtures. Native save/mouse business targets are stop boundaries,
never functions assigned a fabricated successful result.
"""
from pathlib import Path
import json,hashlib,time,sys
import verify_lifecycle as l
from verify_lifecycle import TSE,DATA,Q,I,OS,ns
from unicorn.x86_const import UC_X86_REG_RAX,UC_X86_REG_RDI,UC_X86_REG_RSP
H=Path(__file__).resolve().parent;O=H/'build'

class VM(l.VM):
 def __init__(self):
  super().__init__();self.end_inside_high_raise=False
 def hook(self,u,address,size,opaque):
  if self.end_inside_high_raise and address==self.oh['raise'] and self.arg(0)==31:
   self.end_inside_high_raise=False;old=self.current_tpl;self.current_tpl=31;self.did_end=True
   self.nested(OS['no_end_boot'],[0,0],old);return
  return super().hook(u,address,size,opaque)

def main():
 rows=[]
 def case(name,fn):
  if len(sys.argv)>1 and not any(x.lower()in name.lower()for x in sys.argv[1:]):return
  v=VM();t=time.time()
  try:d=fn(v)
  except Exception as e:
   (O/('nav_failure_'+str(time.time_ns())+'.json')).write_text(json.dumps({'name':name,'error':repr(e),'unknown':v.unknown,'component_sha256':l.SHA,'sequence':v.sequence_values,'transcript':v.transcript[-300:]},indent=2)+'\n');raise
  rows.append({'name':name,'status':'PASS','seconds':round(time.time()-t,3),'observations':d});print(name,d,flush=True)
 def cancel(v,wrong=False):
  pw=b'NavTest5';v.record=ns['core'].signed_record(password=pw);v.ready_full();v.queue('WrongPassword5\r!'if wrong else'\x1b')
  v.loop([(TSE+0x1b928,[0,v.ai]),('n05_first',[]),(TSE+0x1b928,[v.main,v.security]),(TSE+0x1b814,[v.security,DATA+0x29000,DATA+0x29008])])
  assert v.sequence_values[1]==2 and v.sequence_values[-1]==0 and v.index()==v.main and v.used()==2 and not v.set_count
  assert v.r(v.hist(),32)==Q(v.setup_hii)+I(0x2712)+bytes(20) and int.from_bytes(v.r(DATA+0x29000,2),'little')==v.main
  return {'main_index':v.main,'history_records':v.used(),'next_security_back_main':True,'credential_writes':0}
 case('Escape with real-parser data and owned nonempty history returns usable Main',cancel)
 case('wrong password returns Main and preserves original next/back operation',lambda v:cancel(v,True))
 def grant(v):
  pw=b'NavTest5';v.record=ns['core'].signed_record(password=pw);v.ready_full();v.queue(pw.decode()+'\r')
  # The original Loop cleanup retires the history before the private visit
  # ends. Omitting this native fragment would leave a stale previous-visit
  # fixture allocation, for which Main fallback correctly refuses ownership.
  cleanup=(TSE+0x19a5d,[0],{UC_X86_REG_RAX:v.bs,UC_X86_REG_RDI:0,UC_X86_REG_RSP:ns['STACK']+0x1e0000},TSE+0x19a76)
  def prepare_cleanup(w):cleanup[1][0]=w.hist()
  v.loop([(TSE+0x1b928,[0,v.ai]),('n05_first',[]),('n05_first',[]),prepare_cleanup,cleanup])
  assert v.sequence_values[1:3]==[1,1] and v.index()==v.ai and not v.hist() and v.used()==0 and not v.set_count and v.run('w890_provider_query',v.p)==1
  # End of real private Loop ends the grant. A new visit requires input.
  v.sequence_values=[];v.queue('\x1b');v.loop([('n05_first',[])])
  assert v.sequence_values==[2] and v.index()==v.main and not v.set_count
  return {'same_visit_twice':True,'new_visit_requires_password':True,'credential_writes':0}
 case('correct password grants Ai in one visit and a new visit asks again',grant)
 def ordinary(v):
  v.ready_full();v.w(v.app+0x28,I(v.main))
  def security(w):w.w(w.app+0x28,I(w.security))
  v.loop([('n05_first',[]),security,('n05_first',[])])
  assert v.sequence_values==[1,1] and not v.transcript and not v.set_count
  return {'main_and_security':'original ordinary route, no password UI'}
 case('ordinary Main and Security remain available without a password prompt',ordinary)
 def f7(v):
  v.ready_full();v.extra_fixture(0x11);v.w(v.app+0x28,I(v.main));v.loop([('n05_native_app_input',[v.app,v.ev])])
  assert v.sequence_values==[ns['ERR'](3)] and not v.set_count
  return {'original_status':hex(v.sequence_values[0]),'meaning':'ordinary unsupported fallthrough, not swallowed by lock'}
 case('F7 retains its original App-level unsupported fallthrough',f7)
 def target(v,mouse=False):
  v.ready_full();v.extra_fixture(0x14,mouse=mouse);v.w(v.app+0x28,I(v.main));v.boundary=TSE+(0x4af48 if mouse else 0x1fc84)
  name='n05_native_alt_input'if mouse else'n05_native_app_input';obj=v.extra if mouse else v.app
  try:v.loop([(name,[obj,v.ev])])
  except AssertionError:assert v.unknown and v.unknown['pc']==hex(v.boundary)
  else:raise AssertionError('business target unexpectedly modeled complete')
  assert not v.set_count
  return {'status':'STOPPED_UNKNOWN','exact_original_target':hex(v.boundary-TSE),'no_fabricated_status':True}
 case('F10 reaches the unchanged original save-confirm target',target)
 case('mouse hit-test reaches its unchanged original region callback',lambda v:target(v,True))
 def ebspoll(v):
  v.ready_full();v.end_inside_high_raise=True
  assert v.run('n05_recovery_poll',v.app)==2 and v.did_end and not v.efi_after_end and v.waits==0
  return {'injected_boundary':'actual no_end_boot called during modeled RaiseTPL31','later_UEFI_calls':0,'note':'fault-injection boundary, not a claim standard RaiseTPL dispatches EBS'}
 case('recovery poll revalidates before RestoreTPL after injected revocation',ebspoll)
 report={'component_sha256':l.SHA,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'dependency_sha256':l.SOURCE_SHA,'parser_snapshot_sha256':l.f.ZS,'checks':len(rows),'cases':rows,'limits':['Native App/Page/Frame outer containers remain fixtures','F10 and mouse stop at original native business destination; full business function not executed','Initial credential FAULT still needs root restricted-profile integration','No full foreign-page integration or physical installation']}
 (O/('navigation_tests.json'if len(sys.argv)==1 else'navigation_selected_tests.json')).write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(rows))
if __name__=='__main__':main()
