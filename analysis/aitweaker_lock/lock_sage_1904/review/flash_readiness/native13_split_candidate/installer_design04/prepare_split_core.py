"""Seed separate-base guard sources from frozen N12; no firmware installer."""
from pathlib import Path
import hashlib,json,shutil
HERE=Path(__file__).resolve().parent;FR=HERE.parents[1]
OLD=FR/'native12_safety_review/implementation/source';OUT=HERE/'split_core';SRC=OUT/'source'
SRC.mkdir(parents=True,exist_ok=True)
if(SRC/'gate.c').exists():raise FileExistsError('Do not overwrite reviewed split source')
for n in ['efi.h','policy_data.h']:shutil.copyfile(OLD/n,SRC/n)
header=(OLD/'gate.h').read_text().replace('#define GATE_BINDING_MAGIC 0x3430393145544147ULL','#define GATE_BINDING_MAGIC 0x3430393153504c47ULL')
start=header.index('typedef struct {');end=header.index('typedef struct GATE_PROVIDER',start)
header=header[:start]+'''/* RAM_SPLIT_PROFILE_1: original modules and immutable guard allocation are
 * explicitly distinct. No PE SizeOfImage expansion or implicit base rebasing. */
typedef struct {
 uint64_t magic;uint32_t revision,kind;
 uint32_t self_offset,payload_size;
 uint64_t original_base,original_size,guard_base,state_base,state_size;
 uint64_t original_loop,original_frame,original_commit,original_defaults,original_save;
 uint64_t setup_base,setup_size,setup_callback,setup_route,setup_guard,setup_guard_size;
 uint32_t setup_guard_crc,reserved;
} GATE_BINDING;
#define SPLIT_STATE_MAGIC 0x3331535441544547ULL
#define SPLIT_ARMED 1u
#define SPLIT_RETIRED 2u
#define SPLIT_ENDED 3u
typedef struct {void *ui_head,*save_head;uint64_t magic;uint32_t phase,reserved;} SPLIT_STATE;
_Static_assert(sizeof(SPLIT_STATE)==32,"split state layout");
'''+header[end:]
header=header.replace('sizeof(GATE_BINDING)==72','sizeof(GATE_BINDING)==160')
(SRC/'gate.h').write_text(header)
source=(OLD/'gate.c').read_text()
source=source.replace('const volatile GATE_BINDING gate_binding={GATE_BINDING_MAGIC,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};','const volatile GATE_BINDING gate_binding={.magic=GATE_BINDING_MAGIC,.revision=1};')
source=source.replace('0xf29d11ab,0xc12a,0x455a,{0x95,0xd3,0x9a,0x8e,0xcf,0x04,0x5c,0x04}','0x87e3c6fa,0x11fb,0x4e77,{0xaf,0x2d,0xea,0x50,0xb6,0x40,0xfa,0x13}')
start=source.index('uint8_t *gate_base(void){');end=source.index('/* x64 UEFI identity mapping',start)
source=source[:start]+'''uint8_t *gate_base(void){
 uintptr_t own=(uintptr_t)&gate_binding;uint32_t offset=gate_binding.self_offset;
 uint64_t original=gate_binding.original_base,size=gate_binding.original_size;
 if(gate_binding.magic!=GATE_BINDING_MAGIC||gate_binding.revision!=1||
    (gate_binding.kind!=1&&gate_binding.kind!=2)||offset>own||offset>=gate_binding.payload_size||
    gate_binding.payload_size>65536||gate_binding.payload_size-offset<sizeof(gate_binding)||
    gate_binding.guard_base!=own-offset||(gate_binding.guard_base&4095)||
    original<4096||(original&4095)||original>=(1ULL<<47)||size>(1ULL<<47)-original||
    size!=(gate_binding.kind==1?0xa1f40u:0x1a5ca0u))return 0;
 return (uint8_t *)(uintptr_t)original;
}
'''+source[end:]
pos=source.index('static BS *bs(void){')
source=source[:pos]+'''static SPLIT_STATE *split_state(void){
 if(!gate_base()||gate_binding.state_size!=4096||gate_binding.state_base<4096||(gate_binding.state_base&4095))return 0;
 SPLIT_STATE *s=(void *)(uintptr_t)gate_binding.state_base;
 if(!gate_memory(s,sizeof(*s),1)||s->magic!=SPLIT_STATE_MAGIC||s->reserved||
    (s->phase!=SPLIT_ARMED&&s->phase!=SPLIT_RETIRED&&s->phase!=SPLIT_ENDED))return 0;
 return s;
}
static int split_live(void){SPLIT_STATE *s=split_state();return s&&s->phase!=SPLIT_ENDED;}
static int split_armed(void){SPLIT_STATE *s=split_state();return s&&s->phase==SPLIT_ARMED;}
static GATE_FRAME **ui_head(void){SPLIT_STATE *s=split_state();return s?(GATE_FRAME **)&s->ui_head:0;}
'''+source[pos:]
old=''' uint8_t *base=gate_base();UN r=gate_binding.context_rva;
 return base&&gate_binding.kind==1&&r&&r+16<=gate_binding.image_size&&gate_memory(base+r,16,1)?(SAVE_FRAME **)(base+r+8):0;'''
assert old in source
source=source.replace(old,' SPLIT_STATE *s=split_state();return s&&gate_binding.kind==1?(SAVE_FRAME **)&s->save_head:0;')
for old,new in [('gate_base()+gate_binding.original_save_rva','(uint8_t *)(uintptr_t)gate_binding.original_save'),('gate_base()+gate_binding.original_frame_rva','(uint8_t *)(uintptr_t)gate_binding.original_frame'),('base+gate_binding.original_defaults_rva','(uint8_t *)(uintptr_t)gate_binding.original_defaults'),('gate_base()+gate_binding.original_loop_rva','(uint8_t *)(uintptr_t)gate_binding.original_loop'),('base+gate_binding.original_commit_rva','(uint8_t *)(uintptr_t)gate_binding.original_commit'),('gate_binding.image_size','gate_binding.original_size')]:source=source.replace(old,new)
source=source.replace(' BS *b=bs();GATE_PROVIDER *p=0;',' if(!split_armed())return 0;BS *b=bs();GATE_PROVIDER *p=0;',1)
old=''' uintptr_t callback=(uintptr_t)cfg->callback;UN cb=gate_binding.setup_callback_rva,route=gate_binding.setup_route_rva;
 if(!cb || !route || callback<cb)return -1;
 uint8_t *image=(uint8_t *)(callback-cb);'''
assert old in source
source=source.replace(old,''' uintptr_t callback=(uintptr_t)cfg->callback;UN cb=gate_binding.setup_callback,route=gate_binding.setup_route;
 if(!cb||!route||!gate_binding.setup_base)return -1;
 if(callback!=cb||(uintptr_t)cfg->route!=route)return 0;
 uint8_t *image=(uint8_t *)(uintptr_t)gate_binding.setup_base;''')
source=source.replace('if((uintptr_t)cfg->route!=(uintptr_t)image+route)return 0;','if(gate_binding.setup_size!=0x1a5ca0)return -1;')
source=source.replace('if(size<0x1a5ca0 || size>4*1024*1024 || !gate_memory(image,size,0))return -1;','if(size!=gate_binding.setup_size||!gate_memory(image,size,0))return -1;')
old=''' UN gr=gate_binding.setup_gate_rva,gn=gate_binding.setup_gate_size;
 if(gn && (gr>=size || gn>size-gr || crc32(image+gr,gn)!=gate_binding.setup_gate_crc))return -1;'''
assert old in source
source=source.replace(old,''' uint8_t *guard=(void *)(uintptr_t)gate_binding.setup_guard;UN gn=gate_binding.setup_guard_size;
 if(!guard||((uintptr_t)guard&4095)||!gn||gn>65536||!gate_memory(guard,gn,0)||crc32(guard,gn)!=gate_binding.setup_guard_crc)return -1;''')
old='''  UN r=gate_binding.context_rva;
  GATE_FRAME **head=r&&r+8<=gate_binding.original_size?add(base,r):0;'''
assert old in source;source=source.replace(old,'  GATE_FRAME **head=ui_head();')
old=''' uint8_t *base=gate_base();UN r=gate_binding.context_rva;
 GATE_FRAME **head=base&&r&&r+8<=gate_binding.original_size?add(base,r):0;'''
assert old in source;source=source.replace(old,' GATE_FRAME **head=ui_head();')
# Every published entry refuses to call original BootServices code after the
# resident test is ended; RETIRED cached pointers remain resident and deny OC.
returns={'gate_save':'0','gate_render':'0','gate_page_input':'0','gate_app_input':'0','gate_frame_input':'0','gate_defaults':'ERR(15)','gate_navigation':'ERR(15)','gate_poll':None,'gate_loop':'ERR(15)','gate_callback':'ERR(15)','gate_variable_commit':'ERR(15)','gate_route':'ERR(15)'}
import re
for name,value in returns.items():
 pattern=r'((?:ES|uint64_t|void) EA '+name+r'\([^\n]*\)\{)'
 source,count=re.subn(pattern,lambda m:m[1]+'if(!split_live())return'+(' '+value if value else '')+';',source)
 assert count==1,name
(SRC/'gate.c').write_text(source)
(OUT/'source_origins.json').write_text(json.dumps({'status':'NEW_SPLIT_BASE_CORE_ONLY_NO_INSTALLER_OR_PROVIDER','frozen_n12_sources':{n:hashlib.sha256((OLD/n).read_bytes()).hexdigest()for n in ['gate.c','gate.h','efi.h','policy_data.h']},'preserved_policies':'Same twelve dispatch/save policies; only explicit base/state addressing, new provider GUID and ended/retired entry lifecycle checks changed.','public_provider_ABI':'Same five-method layout, isolated GUID 87e3c6fa-11fb-4e77-af2d-ea50b640fa13; N12/provider12 incompatible by GUID.','seed_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},indent=2)+'\n')
print(OUT)
