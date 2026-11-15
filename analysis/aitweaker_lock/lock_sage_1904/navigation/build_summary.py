"""Retain the evidence boundary for the SAGE native adapter."""
from pathlib import Path
import datetime,hashlib,json
HERE=Path(__file__).resolve().parent
def read(p):return json.loads(p.read_text(encoding='utf8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 modules={name:sha(HERE.parent/'analysis/modules'/(name+'.efi')) for name in ['Setup','AMITSE']}
 assert modules=={'Setup':'719bad779e9ae60340187c7aae6c12ab9dff3ee398c58a9fca2a4e027a33f21d','AMITSE':'531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1'}
 eq=read(HERE/'routine_equivalence.json');native=read(HERE.parent/'lab/native_hooks_result.json');adapter=read(HERE.parent/'driver/build/adapter_emulation.json')
 assert len(eq['routines'])==8 and all(r['normalized_bytes_identical'] and r['direct_branch_edges_equal'] for r in eq['routines'])
 assert native['all_passed'] and adapter['status']=='PASS' and adapter['cases']==36
 retained=[]
 for name in ['NAV-15370','NAV-34b7c','NAV-322b4','NAV-11d8c','NAV-11518']:
  p=HERE.parent.parent/'lock_1904/navigation/rea'/(name+'.json');d=read(p)['structuredContent']
  retained.append({'path':str(p),'sha256':sha(p),'evidence_id':d['evidence_id'],'module_scope':'ACE1904; static code/field evidence reused only with separately recorded SAGE opcode/control-flow mapping; not SAGE hardware evidence'})
 fresh=[]
 for p in sorted([*(HERE/'rea').glob('SAGE-*.json'),*(HERE/'rea').glob('FOCUS-*.json')]):
  d=read(p);s=d.get('structuredContent',{});fresh.append({'file':str(p.relative_to(HERE)),'sha256':sha(p),'is_error':d.get('isError',False),'evidence_id':s.get('evidence_id'),'operation':s.get('operation'),'result_keys':list(s)})
 focused=[]
 for name in ['FOCUS-dispatch626c','FOCUS-loop-e1b8','FOCUS-poll34b2c']:
  p=HERE/'rea'/(name+'.json');d=read(p);s=d['structuredContent'];r=s['normalized_result']
  assert not d.get('isError',False) and s['evidence_id']
  focused.append({'file':str(p.relative_to(HERE)),'evidence_id':s['evidence_id'],'address':r['procedure']['address'],'body':r['procedure']['body'],'unresolved_calls':r['unresolved_calls'],'limitations':r['limitations']})
 closed=read(HERE/'rea/plan-focused.final-close.json');assert not closed.get('isError',False) and closed['structuredContent']=={'result':None}
 report={
  'status':'PASS','scope':'STATIC_NATIVE_ADAPTER_AND_BOUNDED_EMULATION_ONLY',
  'generated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
  'module_sha256':modules,'driver_sha256':adapter['driver_sha256'],
  'routine_count':8,'routine_instruction_counts':{r['routine']:r['new_instructions'] for r in eq['routines']},
  'same_non_address_instructions_and_direct_branch_edges':True,
  'native_original_cases':len(native['cases']),'compiled_adapter_cases':adapter['cases'],
  'addresses':read(HERE/'applied_offsets.json')['map'],
  'setup_config_access':{'extract':'0x1524','route':'0x152c','callback':'0x1534','evidence':'Unique anchor mappings of actual SAGE Setup bytes; original pointer checks retained.'},
  'important_finding':'SAGE initial BrowserLoop callback result is ignored just as in ACE. Poll, render, page/app/frame input and configuration/write gates remain necessary; the callback alone is insufficient.',
  'new_sage_forms_tested':['Overclocking Presets 0x2eb8','Memory Presets 0x2eba'],
  'cross_model_rejection':'Actual ACE Setup and AMITSE bytes rejected independently; original callback slots left unchanged.',
  'fresh_rea_records':fresh,'retained_rea_records':retained,
  'fresh_native_function_analysis_complete':True,'fresh_native_functions':focused,
  'rea_recovery':read(HERE/'rea_diagnostics.json'),
  'reproducible_evidence':{str(p.relative_to(HERE)):sha(p) for p in [HERE/'anchor_mapping.json',HERE/'global_mapping.json',HERE/'routine_equivalence.json',HERE/'applied_offsets.json']},
  'hardware_password_tested':False,
  'limits':['No execution of complete ASUS firmware or graphical/EZ/Setup-search UI.',
    'Unicorn firmware services, UI outcomes, memory attributes and whole browser body are explicit stubs.',
    'Direct-call destinations and RIP targets are retained; identical masked code is static corroboration, not proof of every indirect edge.',
    'OEM direct-Del/F2 loading order and actual persistent NVRAM behavior require subsequent device validation.',
    'This port does not validate flashing, capsule signature acceptance or recovery.']
 }
 (HERE/'adaptation_summary.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
 print(json.dumps({k:report[k] for k in ['status','module_sha256','driver_sha256','routine_count','native_original_cases','compiled_adapter_cases']},indent=2))
if __name__=='__main__':main()
