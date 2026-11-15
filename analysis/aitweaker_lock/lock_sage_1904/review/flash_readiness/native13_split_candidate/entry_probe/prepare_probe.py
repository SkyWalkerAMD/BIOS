"""Create isolated read-only entry-context probe inputs from frozen N12 source."""
from pathlib import Path
import hashlib,json,shutil,sys
HERE=Path(__file__).resolve().parent;N13=HERE.parent;CASE=HERE.parents[3];ROOT=CASE.parents[2];N12=HERE.parents[1]/'native12_hardware_candidate'
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
SRC=HERE/'source';SRC.mkdir(parents=True,exist_ok=True)
for p in (N12/'source').rglob('*'):
    if p.is_file():dest=SRC/p.relative_to(N12/'source');dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
kvm=(SRC/'transport/kvm.c').read_text().replace('SAGE NATIVE12 - READ ONLY','SAGE N13 - ENTRY CONTEXT').replace('SAGE N12 preflight - READ ONLY','SAGE N13 entry context - READ ONLY').replace('N12 read-only probe ended.','N13 read-only entry probe ended.')
(SRC/'transport/kvm.c').write_text(kvm)
lines=[];metadata=[]
for index,name in enumerate(['DxeCore','BdsArch']):
    path=N13/'boot_context'/f'{name}.original.efi';p=pefile.PE(str(path));t=next(s for s in p.sections if s.Name.rstrip(b'\0')==b'.text');raw=p.get_data(t.VirtualAddress,t.Misc_VirtualSize);digest=hashlib.sha256(raw).digest();relocs=[]
    for block in p.DIRECTORY_ENTRY_BASERELOC:
        for e in block.entries:
            if e.type and t.VirtualAddress<=e.rva<t.VirtualAddress+t.Misc_VirtualSize:
                assert e.type==10 and e.rva+8<=t.VirtualAddress+t.Misc_VirtualSize;value=int.from_bytes(p.get_data(e.rva,8),'little');assert value<p.OPTIONAL_HEADER.SizeOfImage;relocs.append({'rva':e.rva,'original':value})
    lines.append(f'static const uint8_t extra_hash_{index}[32]={{'+','.join(f'0x{x:02x}'for x in digest)+'};')
    metadata.append({'name':name,'source':str(path),'sha256':sha(path),'size':p.OPTIONAL_HEADER.SizeOfImage,'entry':p.OPTIONAL_HEADER.AddressOfEntryPoint,'text_rva':t.VirtualAddress,'text_size':t.Misc_VirtualSize,'normalized_text_sha256':digest.hex(),'text_relocations':relocs})
lines.append('typedef struct{uint32_t rva;uint64_t original;}TEXT_RELOC;\nstatic const TEXT_RELOC core_relocs[]={')
lines.extend('{'+str(e['rva'])+'u,'+str(e['original'])+'ULL},'for e in metadata[0]['text_relocations']);lines.append('};')
assert not metadata[1]['text_relocations']
lines.append('static const TARGET extra_targets[2]={')
for i,m in enumerate(metadata):lines.append('{"'+m['name']+'",'+','.join(str(m[k])+'u'for k in['size','size','entry','text_rva','text_size'])+',extra_hash_'+str(i)+'},')
lines.append('};')
(SRC/'context_binding.h').write_text('\n'.join(lines)+'\n')
source=(N12/'source/preflight.c').read_text();source=source.replace('#include "targets.h"','#include "targets.h"\n#include "context_binding.h"')
source=source.replace('char probe_log[24576];UN probe_log_bytes;','char probe_log[24576];UN probe_log_bytes;\ntypedef struct{UN rsp,rbp,rbx,rsi,rdi,r12,r13,r14,r15,image,st;}ENTRY_CAPTURE;\nENTRY_CAPTURE captured_entry;\nstatic LOADED *extra_loaded[2];static uint8_t *extra_images[2];static unsigned extra_found[2],extra_valid[2];\nstatic GUID bds_file_guid={0x8f4b8f82,0x9b91,0x4028,{0x86,0xe6,0xf4,0xdb,0x7d,0x4c,0x1d,0xff}};')
source=source.replace('int collect(ST *st){','#include "context_inspect.inc"\nint collect(ST *st){')
source=source.replace('log_overflow=writing_footer=0;','log_overflow=writing_footer=0;memset(extra_loaded,0,sizeof(extra_loaded));memset(extra_found,0,sizeof(extra_found));memset(extra_valid,0,sizeof(extra_valid));')
old='LOADED *li=0;GUID guid;if(FAILED(st->bs->handle_protocol(handles[i],&loaded_guid,(void **)&li))||!refresh_map()||!readable(li,sizeof(*li))||!image_guid(li,&guid))continue;'
new='LOADED *li=0;GUID guid;if(FAILED(st->bs->handle_protocol(handles[i],&loaded_guid,(void **)&li))||!refresh_map()||!readable(li,sizeof(*li)))continue;\n  uintptr_t start=(uintptr_t)st->bs->start_image;if(start>=0x8720&&(uintptr_t)li->image_base==start-0x8720){extra_found[0]++;extra_loaded[0]=li;}\n  if(!image_guid(li,&guid))continue;\n  if(!memcmp(&guid,&bds_file_guid,16)){extra_found[1]++;extra_loaded[1]=li;}'
assert old in source;source=source.replace(old,new)
source=source.replace('inspect_module(0);inspect_module(1);inspect_interfaces();','inspect_module(0);inspect_module(1);inspect_interfaces();inspect_entry_context();')
source=source.replace('SAGE_NATIVE12_READONLY_PREFLIGHT','SAGE_NATIVE13_ENTRY_CONTEXT_READONLY').replace('SAGE_NATIVE12_PREFLIGHT_END','SAGE_NATIVE13_ENTRY_CONTEXT_END')
source=source.replace('ES EA efi_main(HANDLE image,ST *st){','ES EA probe_main(HANDLE image,ST *st){')
(SRC/'preflight.c').write_text(source)
build=(N12/'build_probe.py').read_text().replace('CASE=HERE.parents[2]','CASE=HERE.parents[3]').replace("'transport/vendor/qrcodegen.c']","'transport/vendor/qrcodegen.c','entry.S']")
build=build.replace('SageNative12ReadOnlyPreflight','SageNative13EntryContext').replace('SAGE-NATIVE12-READONLY-PREFLIGHT','SAGE-N13-READONLY-ENTRY-CONTEXT').replace("label='N12PROBE'","label='N13CONTEXT'").replace("vol_ident='SAGE_N12_PROBE'","vol_ident='SAGE_N13_CTX'")
build=build.replace('commands=[];objects=[]',"(BUILD/'tmp').mkdir(exist_ok=True);env.update(TMP=str(BUILD/'tmp'),TEMP=str(BUILD/'tmp'));commands=[];objects=[]")
(HERE/'build_probe.py').write_text(build)
report={'status':'READ_ONLY_CONTEXT_BINDING','baseline_probe_manifest_sha256':sha(N12/'preflight_manifest.json'),'extra_modules':metadata,'fixed_frame_report_sha256':sha(N13/'startimage_frame_verification.json'),'core_startimage_rva':0x8720,'core_entry_call_rva':0x88ac,'core_entry_return_rva':0x88af,'parent_return_stack_offset':0x60,'core_saved_image_handle_offset':0x68,'parent_saved_rbp_stack_offset':0x78,'scope':'Captures only a verified fixed Core StartImage frame and one native parent return. No generic unwind or browser-absence proof.'}
(HERE/'identity_binding.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'modules':len(metadata),'core_text_relocations':len(metadata[0]['text_relocations'])}))
