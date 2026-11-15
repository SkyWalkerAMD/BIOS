"""Independent six-entry replay of actual compiled native12 save feedback.

Only the bound module root differs from the frozen counterexample fixture.
No return value, save result, branch or exit/reset field is intercepted.
"""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
source=HERE/'replay_ui_feedback.py';snapshot=HERE/'input-native-harness.py'
text=source.read_text().replace("exec(compile(snapshot.read_text(),str(snapshot),'exec'),m.__dict__)",
 "exec(compile(snapshot.read_text().replace(\"OLD=DEST.parent/'cold_entry_candidate/implementation'\",\"OLD=DEST/'implementation'\"),str(snapshot),'exec'),m.__dict__)")
ns={'__file__':str(source),'__name__':'frozen_counterexample_fixture'}
exec(compile(text,str(source),'exec'),ns)
m=ns['m'];Base=ns['FeedbackVM'];rows=[]
for entry in ['F10','mouse-save-exit','exit-action-save-exit','exit-action-save-reset','exit-action-save-stay','submit-callback-branch']:
 for mode in ['changed-protected','missing-protected','unchanged','unrelated-memory-byte']:
  v=Base(counterfactual=False,changed=mode=='changed-protected')
  if mode=='missing-protected':v.missing.add(m.MEM)
  if mode=='unrelated-memory-byte':
   fresh=bytearray(v.variables[m.MEM]);fresh[0x11]=0x5a;v.set_cache(92,fresh)
  r=v.invoke(entry);r['mode']=mode
  denied=mode in ['changed-protected','missing-protected'];expected=int(not denied)
  assert r['substitutions']==0 and not v.counterfactual
  assert r['protected_commit_status']==(hex(m.ERR(15)) if denied else '0x0')
  assert r['protected_writes']==expected
  assert r['save_boolean_results']==[1] # original body still returns its real TRUE
  assert r['original_save_iterator_commits']==116
  assert r['exit_byte']==(0 if entry=='exit-action-save-stay' else expected)
  if denied:assert r['reset_flags']==[0,0]
  if entry=='exit-action-save-stay':assert r['reset_flags'][1]==expected
  if mode=='unrelated-memory-byte':assert v.variables[m.MEM][0x11]==0x5a
  private=m.TSE+int(m.manifest['modules']['AMITSE']['context_head_rva'],16)+8
  assert v.getq(private)==0
  r['private_scope_head_after']=0
  rows.append(r)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
report={'status':'PASS_ACTUAL_NATIVE12_SIX_SAVE_CALLERS_WITH_EXPLICIT_IO_FIXTURES','cases':len(rows),'rows':rows,
        'module_sha256':{k:v['sha256'] for k,v in m.manifest['modules'].items()},
        'counterfactual_return_interventions':0,'source_sha256':sha(Path(__file__)),
        'inherited_fixture_sha256':sha(source),'frozen_harness_snapshot_sha256':sha(snapshot),
        'scope':'Original save iteration and all identified caller branches execute with real compiled save scope. Only services, runtime cache, confirmation dialog and declared OEM side effects are fixtures.',
        'limits':['This is not an ASUS full GUI or hardware/NVRAM test.',
                  'Submit callback starts at the identified save branch, not the complete enclosing callback.',
                  'Denied Save-Stay still clears original state byte83578, and the original post-save callbacks are fixtures. Full graphical feedback/cache behavior remains unaccepted.',
                  'Unrelated variables can be committed in a save that rejects protected changes; no transaction/rollback is claimed.',
                  'Only ACCESS_DENIED aggregation is added; other original status handling is unchanged.']}
(HERE/'native12_feedback_verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'cases':len(rows),'module_sha256':report['module_sha256']}))
