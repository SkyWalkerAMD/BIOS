"""Actual OEM save iterator and callers; explicit service/cache/UI fixtures.

The counterfactual arm substitutes only the final save BOOLEAN to determine
whether callers already propagate failure. It is NOT a new compiled fix.
"""
from pathlib import Path
import hashlib, json, types
OUT=Path(__file__).resolve().parent
hp=OUT.parent/'native12_safety_review/native_harness.py'
snapshot=OUT/'input-native-harness.py'
m=types.ModuleType('native_init_fixture');m.__file__=str(hp)
exec(compile(snapshot.read_text(),str(snapshot),'exec'),m.__dict__)
TSE=m.TSE;U=m.U;R=m.R;HEAP=m.HEAP

class FeedbackVM(m.InitializationVM):
 def __init__(self, counterfactual=False, changed=True):
  self.counterfactual=counterfactual;self.boolean_substitutions=0;self.confirmations=[]
  super().__init__()
  self.u.mem_write(TSE+0x83588,m.q(self.app));self.u.mem_write(self.app+0x28,m.d(0))
  self.u.mem_write(TSE+0x83580,b'\0\0');self.u.mem_write(self.app+0x5a,b'\0')
  self.u.mem_write(TSE+0x83578,b'\1')
  self.set_cache(88,self.variables[m.OC])
  fresh=bytearray(self.variables[m.MEM]);fresh[0x10]=int(changed);self.set_cache(92,fresh)
  for r in [0x19ea4,0x609c]:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=TSE+r,end=TSE+r)
 def hook(self,u,a,n,data):
  if a==TSE+0x19ea4:self.confirmations.append(self.arg(1));self.ret(0);return
  if a==TSE+0x609c:self.ret(0x14);return
  if a==TSE+0x148a2 and self.counterfactual and any(int(x['status'],16)>>63 for x in self.commit_status):
   u.reg_write(R.UC_X86_REG_RAX,u.reg_read(R.UC_X86_REG_RAX)&~255);self.boolean_substitutions+=1
  super().hook(u,a,n,data)
 def invoke(self,entry):
  if entry=='F10':self.call(TSE+0x330a8,self.app)
  elif entry=='mouse-save-exit':
   control=HEAP+0x130000;menu=HEAP+0x131000
   self.u.mem_write(self.app+0x20,m.q(control));self.u.mem_write(control+12,m.d(7));self.u.mem_write(menu+0x24,m.d(0))
   self.call(TSE+0x33188,self.app,menu)
  elif entry=='exit-action-save-exit':self.call(TSE+0x448cc)
  elif entry=='exit-action-save-reset':self.call(TSE+0x448fc)
  elif entry=='exit-action-save-stay':self.call(TSE+0x44968)
  elif entry=='submit-callback-branch':self.native_site(0x1e66b,0x1e6aa)
  else:raise ValueError(entry)
  protected=[x for x in self.commit_status if x['index']==92]
  assert len(protected)==1
  return {'entry':entry,'protected_commit_status':protected[0]['status'],
          'protected_writes':len([x for x in self.set_calls if x['name']==m.MEM]),
          'exit_byte':self.u.mem_read(self.app+0x5a,1)[0],
          'reset_flags':list(self.u.mem_read(TSE+0x83580,2)),
          'oem_state_byte_83578_before':1,'oem_state_byte_83578_after':self.u.mem_read(TSE+0x83578,1)[0],
          'save_boolean_results':self.save_results,'substitutions':self.boolean_substitutions,
          'original_save_iterator_commits':len(self.commit_status),'fixture_calls':sorted(set(self.fixture_calls))}

def main():
 rows=[]
 for entry in ['F10','mouse-save-exit','exit-action-save-exit','exit-action-save-reset','exit-action-save-stay','submit-callback-branch']:
  for mode,substitute,changed in [('frozen-denied',False,True),('counterfactual-propagated',True,True),('frozen-unchanged',False,False)]:
   v=FeedbackVM(substitute,changed);r=v.invoke(entry);r['mode']=mode
   assert r['protected_commit_status']==(hex(m.ERR(15)) if changed else '0x0')
   assert r['protected_writes']==(0 if changed else 1)
   expected=0 if substitute else 1
   assert r['save_boolean_results']==[expected]
   if entry!='exit-action-save-stay':assert r['exit_byte']==expected
   else:
    assert r['exit_byte']==0 and r['reset_flags'][1]==expected
    assert r['oem_state_byte_83578_after']==0
   if substitute:assert r['reset_flags']==[0,0] and r['substitutions']==1
   rows.append(r)
 report={'status':'OEM_FEEDBACK_COUNTEREXAMPLES_AND_BOOLEAN_CONTRACT_REPRODUCED','cases':len(rows),'rows':rows,
         'frozen_module_sha256':m.manifest['modules']['AMITSE']['sha256'],
         'harness_source_snapshot':str(snapshot),'harness_sha256':hashlib.sha256(snapshot.read_bytes()).hexdigest(),'test_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'interpretation':['Frozen NATIVE11 denies the protected memory write yet the full OEM save iterator returns TRUE, causing save/exit callers to request exit/reset.',
                           'Replacing only the final save BOOLEAN with FALSE causes all six inspected callers to retain the interface without new reset flags. This supports a bounded save-scope error propagation design.',
                           'Save-Stay 44968 still clears OEM state byte 83578 even when save returns FALSE. Its whole-UI meaning remains to be traced; returning FALSE alone does not establish complete save feedback.'],
         'limits':['This is not a compiled fix: the counterfactual arm uses a declared final-return intervention.',
                   'Runtime cache, services, confirmation dialog, OEM events and certain cleanup functions are fixtures; the original 1425C iteration and caller branch instructions execute.',
                   'The submit callback enters at its identified save branch, not the full enclosing callback.',
                   'Partial unrelated writes can occur before/after a denied protected write. No transaction or full graphical save UX is claimed.',
                   'No hardware, firmware mutation, NVRAM or runtime page permission test.']}
 (OUT/'feedback_verification.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'cases':len(rows)}))

if __name__=='__main__':main()
