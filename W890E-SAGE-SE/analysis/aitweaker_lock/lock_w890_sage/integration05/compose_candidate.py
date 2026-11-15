"""Offline analysis-only PE; not a capsule, not a flash/update artifact."""
from pathlib import Path
import json,hashlib,sys
H=Path(__file__).resolve().parent;B=H.parent
sys.path.insert(0,str(B/'packaging05'))
from merge_pe import compose
from bind_layout import bind_layout
ext=(H/'aggregate_build/W890StaticAggregate05.UNBOUND.TESTONLY.dll').read_bytes()
patches=[];pointers=[]
for p in json.loads((H/'static_windows.json').read_text())['bridges']:
 patches.append(dict(rva=p['rva'],original_hex=p['original'],export=p['export'],mode=p['mode'],trampoline=p['trampoline_name']))
plan=json.loads((B/'navigation05/bridges_build/static_hook_plan.json').read_text())
for p in plan['records']:
 if p['kind']=='pointer64':pointers.append(dict(rva=p['rva'],original_value=p['original_target_rva'],export=p['export']))
 else:
  q=dict(rva=p['rva'],original_hex=p['original'],export=p['export'],mode='jmp'if p['kind']=='jump'else'call')
  if p.get('trampoline_required'):q['trampoline']='i05_original_form_open'
  patches.append(q)
for p in plan['history_records']:
 patches.append(dict(rva=p['rva'],original_hex=p['original'],export=p['target'],mode='call'if p['length']==5 else'jmp'))
for p in json.loads((B/'write_sinks05/patch_contract05.json').read_text())['patches']:
 q=dict(rva=int(p['rva'],0),original_hex=p['original'],export=p['destination'],mode='jmp',trampoline=p['trampoline'].replace('ws05_original_','i05_original_'))
 if q['rva']==0xfd6c:q['export']='i05_dispatch'
 q['pc_relative_targets']=[dict(rva=int(x['rva'],0),target=int(x['target'],0),kind=x['kind'])for x in p['pc_relative_targets']]
 patches.append(q)
internal=json.loads((H/'aggregate_build/internal_symbols.json').read_text())
raw,report=compose(ext,hashlib.sha256(ext).hexdigest(),'i05_entry',patches,pointers,internal)
raw,report=bind_layout(raw,report)
out=H/'aggregate_build/W890Merged05.ANALYSIS_ONLY.efi';out.write_bytes(raw)
(H/'aggregate_build/composition.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':'OFFLINE_PE_ONLY_NOT_FLASHABLE','path':str(out),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'image_size':report['image_size'],'patches':len(patches),'pointers':len(pointers)}))
