"""Derive separate precise Core allocation-rounding diagnostic revision."""
from pathlib import Path
import hashlib,json,shutil
HERE=Path(__file__).resolve().parent;OLD=HERE.parent/'entry_probe'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((OLD/'entry_context_manifest.json').read_text())
for a in manifest['artifacts']:assert sha(HERE.parent/a['path'])==a['sha256'],a['path']
for p in (OLD/'source').rglob('*'):
    if p.is_file():dest=HERE/'source'/p.relative_to(OLD/'source');dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
replacements={'SageNative13EntryContext':'SageNative13EntryContext02','SAGE-N13-READONLY-ENTRY-CONTEXT':'SAGE-N13-READONLY-ENTRY-CONTEXT02','SAGE_NATIVE13_ENTRY_CONTEXT_READONLY':'SAGE_NATIVE13_ENTRY_CONTEXT02_READONLY','SAGE_NATIVE13_ENTRY_CONTEXT_END':'SAGE_NATIVE13_ENTRY_CONTEXT02_END','SAGE N13 - ENTRY CONTEXT':'SAGE N13 - ENTRY CONTEXT02','SAGE N13 entry context - READ ONLY':'SAGE N13 context02 - READ ONLY','N13 read-only entry probe ended.':'N13 context02 read-only probe ended.'}
for name in ['build_probe.py','run_ovmf_probe.py','decode_probe.py']:
    s=(OLD/name).read_text()
    for a,b in replacements.items():s=s.replace(a,b)
    (HERE/name).write_text(s)
for name in ['preflight.c','transport/kvm.c']:
    p=HERE/'source'/name;s=p.read_text()
    for a,b in replacements.items():s=s.replace(a,b)
    p.write_text(s)
p=HERE/'source/context_inspect.inc';s=p.read_text()
old='if(li->image_size!=t->old_size||((uintptr_t)p&4095)||!readable(p,64))return 0;uint32_t pe=u32(p+0x3c);\n if(u16(p)!=0x5a4d||pe<0x40||pe>0x800||pe+0x108>t->old_size||!readable(p+pe,0x108)||u32(p+pe)!=0x4550||u16(p+pe+4)!=0x8664||u16(p+pe+24)!=0x20b||u32(p+pe+40)!=t->entry||u32(p+pe+80)!=t->old_size)return 0;'
new='UN accepted_size=li->image_size,rounded=((UN)t->old_size+4095)&~4095ULL;\n int size_ok=accepted_size==t->old_size||(index==0&&accepted_size==rounded);result("exact or precisely Core-rounded LoadedImage size",size_ok);\n if(!size_ok||((uintptr_t)p&4095)||!readable(p,64))return 0;uint32_t pe=u32(p+0x3c);\n if(u16(p)!=0x5a4d||pe<0x40||pe>0x800||pe+0x108>t->old_size||!readable(p+pe,0x108))return 0;\n number("ContextPEImageSize",u32(p+pe+80));number("ContextPEEntryRVA",u32(p+pe+40));\n int header_ok=u32(p+pe)==0x4550&&u16(p+pe+4)==0x8664&&u16(p+pe+24)==0x20b&&u32(p+pe+40)==t->entry&&u32(p+pe+80)==t->old_size;result("exact original PE size entry and architecture",header_ok);if(!header_ok)return 0;\n uint8_t header_snapshot[0x108];memcpy(header_snapshot,p+pe,sizeof(header_snapshot));\n add(accepted_size==t->old_size?"CoreAllocationRoundingUsed=NO\\r\\n":"CoreAllocationRoundingUsed=YES\\r\\n");\n number("ContextReadExtentBytes",t->old_size);add("ALLOCATION_TAIL_CONTENT_NOT_READ\\r\\n");'
assert old in s;s=s.replace(old,new)
s=s.replace('li->image_base==p&&li->image_size==t->old_size&&readable(p+t->text_rva,t->text_size)','li->image_base==p&&li->image_size==accepted_size&&readable(p,64)&&u16(p)==0x5a4d&&u32(p+0x3c)==pe&&readable(p+pe,sizeof(header_snapshot))&&!memcmp(header_snapshot,p+pe,sizeof(header_snapshot))&&readable(p+t->text_rva,t->text_size)')
s=s.replace('!refresh_map()||!stack_frame_readable(captured_entry.rsp,8)){result("entry capture and bounded stack slot",0);goto done;}', '!refresh_map()){result("entry capture metadata and memory map",0);goto done;}\n const MD *stack_desc=descriptor(captured_entry.rsp);if(stack_desc){number("EntryStackMemoryType",stack_desc->type);number("EntryStackMemoryMapAttributes",stack_desc->attrs);}else add("EntryStackDescriptor=UNKNOWN\\r\\n");\n if(!stack_frame_readable(captured_entry.rsp,8)){result("entry capture and bounded stack slot",0);goto done;}')
p.write_text(s)
binding=json.loads((OLD/'identity_binding.json').read_text());binding.update(revision='ENTRY_CONTEXT02_CORE_ALLOCATION_ROUNDING',predecessor_manifest_sha256=sha(OLD/'entry_context_manifest.json'),hardware_review_sha256=sha(HERE.parent/'entry_hardware_readonly_review.json'),core_metadata_allowed_sizes=[0x20e60,0x21000],core_live_pe_size_required=0x20e60,core_content_read_limit=0x20e60,allocation_tail_read=False)
(HERE/'identity_binding.json').write_text(json.dumps(binding,indent=2)+'\n');print(json.dumps({'revision':binding['revision'],'core_sizes':binding['core_metadata_allowed_sizes']}))
