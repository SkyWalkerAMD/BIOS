"""Prepare a read-only probe. Never prepares or installs native detours."""
from pathlib import Path
import hashlib,json,shutil,sys
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
SRC=HERE/'source';SRC.mkdir(parents=True,exist_ok=True)
P12=HERE.parent/'native_provider12_candidate';OLD=CASE/'remote_172_20_2_162/ram_test/source'
for name in ['efi.h','password_core.h','password_crypto.c']:shutil.copyfile(P12/'source'/name,SRC/name)
for name in ['kvm.h','efi_min.h','probe_core.h','probe_core.c']:
    (SRC/'transport').mkdir(exist_ok=True);shutil.copyfile(OLD/'p3'/name,SRC/'transport'/name)
for dirname in ['vendor','compat']:shutil.copytree(OLD/'p3'/dirname,SRC/'transport'/dirname,dirs_exist_ok=True)
text=(OLD/'kvm.c').read_text();text=text.replace('AI TWEAKER SAGE P5 - RAM TEST','SAGE NATIVE12 - READ ONLY').replace('Ai Tweaker P3 KVM - diagnostic only','SAGE N12 preflight - READ ONLY').replace('P3 KVM ended. Log was displayed, not saved to disk.','N12 read-only probe ended. No hooks or writes were installed.')
(SRC/'transport/kvm.c').write_text(text)
build=json.loads((HERE.parent/'native12_safety_review/implementation/build/build.json').read_text())
lines=['/* Original image identity and NATIVE12 memory requirements. */']
modules=[];patches=[]
for index,name in enumerate(['AMITSE','Setup']):
    path=CASE/'analysis/modules'/(name+'.efi');p=pefile.PE(str(path));item=build['modules'][name];assert sha(path)==item['original_sha256']
    t=next(s for s in p.sections if s.Name.rstrip(b'\0')==b'.text')
    assert not any(e.type and t.VirtualAddress<=e.rva<t.VirtualAddress+t.Misc_VirtualSize for b in p.DIRECTORY_ENTRY_BASERELOC for e in b.entries)
    digest=hashlib.sha256(p.get_data(t.VirtualAddress,t.Misc_VirtualSize)).hexdigest()
    lines.append(f'static const uint8_t text_hash_{index}[32]={{'+','.join('0x'+digest[i:i+2]for i in range(0,64,2))+'};')
    modules.append({'name':name,'original_file_sha256':sha(path),'original_size':p.OPTIONAL_HEADER.SizeOfImage,'entry':p.OPTIONAL_HEADER.AddressOfEntryPoint,
                    'text_rva':t.VirtualAddress,'text_size':t.Misc_VirtualSize,'text_sha256':digest,'new_size':item['bytes'],
                    'additional_pages':((item['bytes']+4095)//4096)-((p.OPTIONAL_HEADER.SizeOfImage+4095)//4096),
                    'allocation_tail_before_next_page':(-p.OPTIONAL_HEADER.SizeOfImage)%4096,'native_sha256':item['sha256']})
    for patch in item['patches']:
        rva=int(patch['rva'],16);pointer=patch['kind']=='DIR64 slot';length=8 if pointer else patch.get('bytes',5)
        raw=p.get_data(rva,length);expected=int(patch['old_rva'],16)if pointer else 0
        if pointer:assert int.from_bytes(raw,'little')==expected
        patches.append({'module':index,'name':patch['entry'],'rva':rva,'pointer':pointer,'expected_rva':expected,'bytes':raw.hex(),'length':length})
lines.append('static const TARGET expected_targets[2]={')
for i,m in enumerate(modules):lines.append('{"'+m['name']+'",'+','.join(str(m[k])+'u'for k in ['original_size','new_size','entry','text_rva','text_size'])+',text_hash_'+str(i)+'},')
lines.append('};\nstatic const PATCH expected_patches[]={')
for p in patches:lines.append('{"'+p['name']+'",'+','.join(str(p[k])+'u'for k in ['module','rva','length'])+','+str(int(p['pointer']))+','+str(p['expected_rva'])+'u,{'+','.join('0x'+p['bytes'][i:i+2]for i in range(0,len(p['bytes']),2))+'}},')
lines.append('};')
(SRC/'targets.h').write_text('\n'.join(lines)+'\n')
report={'status':'READ_ONLY_PREFLIGHT_IDENTITY_BINDING','modules':modules,'patches':patches,'native_provider_sha256':sha(P12/'build/AiTweakerNativeProvider1904.UNSIGNED.review.efi'),
        'source_native12_build_sha256':sha(HERE.parent/'native12_safety_review/implementation/build/build.json'),'probe_has_installer':False,
        'limitations':['MemoryMap ConventionalMemory is availability only, never allocation ownership.','Stage, HII and SendForm identity cannot prove an absent active browser stack.']}
(HERE/'identity_binding.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'modules':len(modules),'patches':len(patches),'additional_pages':[m['additional_pages']for m in modules]}))
