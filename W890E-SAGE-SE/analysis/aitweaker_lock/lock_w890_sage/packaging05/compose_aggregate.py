"""Compose a concrete development PE from actual current component contracts.

No CAP/ROM, signing key or updater action. The .pe output is an unqualified
internal firmware module for offline tests and cannot be flashed as a BIOS.
Each run snapshots inputs so concurrent development does not alter its meaning.
"""
from bind_layout import *
from datetime import datetime,timezone

def integer(v):return int(v,0)if isinstance(v,str)else v

def contracts():
    paths={
      'aggregate':BASE/'integration05/aggregate_build/W890StaticAggregate05.UNBOUND.TESTONLY.dll',
      'build':BASE/'integration05/aggregate_build/build.json',
      'consumers':BASE/'integration05/aggregate_build/internal_symbols.json',
      'lifecycle':BASE/'integration05/static_windows.json',
      'navigation':BASE/'navigation05/bridges_build/static_hook_plan.json',
      'writes':BASE/'write_sinks05/patch_contract05.json'}
    raw={k:p.read_bytes()for k,p in paths.items()};x={k:json.loads(v)for k,v in raw.items()if k!='aggregate'}
    need(sha(raw['aggregate'])==x['build']['sha256'],'aggregate manifest snapshot')
    need(x['lifecycle']['original_amitsesha256']==x['navigation']['original_sha256']==x['writes']['amitsesha256']==ORIGINAL_SHA,'all contracts exact original')
    patches=[];pointers=[]
    for r in x['lifecycle']['bridges']:
        patches.append({'rva':r['rva'],'original_hex':r['original'],'export':r['export'],'mode':r['mode'],'trampoline':r['trampoline_name']})
    for r in x['navigation']['records']:
        if r['kind']=='pointer64':
            pointers.append({'rva':r['rva'],'original_value':r['original_target_rva'],'export':r['export']});continue
        q={'rva':r['rva'],'original_hex':r['original'],'export':r['export'],'mode':'call'if r['kind']=='call'else'jmp'}
        if r.get('trampoline_required'):
            need(r['rva']==0x3f414,'only reviewed navigation trampoline');q['trampoline']='i05_original_form_open'
        patches.append(q)
    for r in x['navigation']['history_records']:
        patches.append({'rva':r['rva'],'original_hex':r['original'],'export':r['target'],'mode':'call'if r['replacement'].startswith('E8')else'jmp'})
    for r in x['writes']['patches']:
        need(r['module']=='AMITSE','no unreviewed Setup modifications')
        destination=r['destination']
        if integer(r['rva'])==0xfd6c:
            need(destination in ('ws05_native_dispatch','i05_dispatch'),'known original dispatch contract')
            # Ordinary native callbacks exist before services/provider binding.
            # The static bootstrap wrapper delegates only ordinary selectors
            # through the fixed original trampoline before full initialization.
            destination='i05_dispatch'
        patches.append({'rva':integer(r['rva']),'original_hex':r['original'],'export':destination,'mode':'jmp',
          'trampoline':r['trampoline'].replace('ws05_original_','i05_original_'),
          'pc_relative_targets':[{'rva':integer(t['rva']),'target':integer(t['target']),'kind':t['kind']}for t in r['pc_relative_targets']]})
    patches.sort(key=lambda r:r['rva']);pointers.sort(key=lambda r:r['rva'])
    # Review the current recipe, never infer a completed protection proof from count.
    need({0x190f4,0x36da4,0x40d94,0x19463,0x3f414,0x1fd58,0xfd6c,0x1f4ac,0x851a4}<=set(p['rva']for p in patches),'required major entries missing')
    need(all(p['rva']!=0x6480 for p in patches),'original cold entry must remain byte exact')
    return paths,raw,x,patches,pointers

def compose_current():
    paths,raw,x,patches,pointers=contracts()
    candidate,report=compose(raw['aggregate'],sha(raw['aggregate']),x['lifecycle']['entry_export'],patches,pointers,x['consumers'])
    candidate,report=bind_layout(candidate,report)
    # Detect a simultaneous writer before snapshotting rather than mixing builds.
    for k,p in paths.items():need(p.read_bytes()==raw[k],'input changed during composition: '+k)
    return candidate,report,paths,raw

def main():
    candidate,report,paths,raw=compose_current()
    out=HERE/'aggregate_runs'/datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S');out.mkdir(parents=True)
    for k,v in raw.items():(out/(k+('.dll'if k=='aggregate'else'.json'))).write_bytes(v)
    output=out/'AMITSE.Static05.DEVELOPMENT.pe';output.write_bytes(candidate)
    report.update(status='COMPOSED_ACTUAL_AGGREGATE_DEVELOPMENT_MODULE_NOT_FLASHABLE',output=str(output),
      internal_module_saved=True,saved_firmware_candidate=False,
      open_qualification=['Complete original-native UI entry and preparse lifecycle tests',
        'Navigation component regressions passed with explicit callback/UI models; actual aggregate full GUI not proven',
        'Foreign HII producer/dynamic-page binding and nonempty pending queue are incomplete',
        'Original parser SPF boundary failure reproduced in original and modified fixtures; full lifecycle remains unproved',
        'Nested effect ticket during native FormOpen and profile callback needs integration proof',
        'Credential fault ordinary-page behavior',
        'Physical board function, full update acceptance, boot policy and recovery'],
      inputs=[{'path':str(paths[k]),'snapshot':str(out/(k+('.dll'if k=='aggregate'else'.json'))),'sha256':sha(v)}for k,v in raw.items()],
      implementation=[{'path':str(p),'sha256':sha(p.read_bytes())}for p in [HERE/'compose_aggregate.py',HERE/'merge_pe.py',HERE/'bind_layout.py',HERE/'layout.c',HERE/'layout.h']])
    (out/'composition.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    (HERE/'latest_aggregate.json').write_text(json.dumps({'report':str(out/'composition.json'),'pe':str(output),'sha256':sha(candidate),'release_ready':False},indent=2)+'\n')
    print(json.dumps({'status':report['status'],'report':str(out/'composition.json'),'bytes':len(candidate),'image_size':report['image_size'],'text_bridges':len(report['patches']),'data_pointers':len(report['pointer_patches'])}))
if __name__=='__main__':main()
