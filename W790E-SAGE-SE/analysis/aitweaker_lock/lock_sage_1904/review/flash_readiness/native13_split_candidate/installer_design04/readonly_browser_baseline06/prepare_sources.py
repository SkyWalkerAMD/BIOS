"""Copy only reviewed read-only primitives; never modify a frozen input."""
from pathlib import Path
import hashlib,json,re,shutil
HERE=Path(__file__).resolve().parent;D04=HERE.parent;TX=D04/'ram_transaction05';SRC=HERE/'source';SRC.mkdir(parents=True,exist_ok=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(TX/'ram_candidate_manifest.json')=='1b9f3b1979855cf3a20b2101c84983854500f3f57f8fefbcdab6c3bf8cd20925'
bindings=[]
def copy(name):
    p=TX/'source'/name;out=SRC/name;out.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,out);bindings.append({'source':str(p),'source_sha256':sha(p),'output':str(out.relative_to(HERE)),'output_sha256':sha(out)})
for name in ['efi.h','entry.S','targets.h','context_binding.h','launch_binding.h','platform_readonly.inc']:copy(name)
for p in (TX/'source/transport').rglob('*'):
    if p.is_file():copy(str(p.relative_to(TX/'source')))
e=(SRC/'efi.h').read_text();e=e.replace('typedef ES (EA *SETVAR)(C16 *,GUID *,uint32_t,UN,void *);','/* No variable-write callable type in this baseline. */').replace('void *next_variable; SETVAR set_variable;','void *next_variable; void *set_variable;')
(SRC/'efi.h').write_text(e)
k=SRC/'transport/kvm.c';text=k.read_text().replace('RAM_TEST05','BROWSER_BASELINE06').replace('SAGE N13 - RAM TEST05','SAGE N13 BROWSER BASELINE06').replace('SAGE N13 RAM TEST05','SAGE N13 BROWSER BASELINE06').replace('RAM TEST LOG - CHECK RESULTS','BROWSER BASELINE - CHECK RESULTS');k.write_text(text)
crypto=(TX/'source/password_crypto.c').read_text();crypto=crypto[:crypto.index('static void hmac_init')];crypto=crypto.replace('#include "password_core.h"','#include "baseline.h"').replace('typedef struct { SHA inner, outer; } HMAC;','').replace('AP_API ','')
crypto=crypto[crypto.index('#include'):];(SRC/'sha256.c').write_text('/* Exact SHA-256/zero/equality subset; no HMAC, KDF or password operations. */\n'+crypto)
bindings.append({'source':str(TX/'source/password_crypto.c'),'source_sha256':sha(TX/'source/password_crypto.c'),'operation':'SHA256-only prefix through ap_sha256; discard all HMAC/PBKDF2 code','output':'source/sha256.c','output_sha256':sha(SRC/'sha256.c')})
p=D04/'provider13/source/management_package.h';shutil.copyfile(p,SRC/'management_package.h');bindings.append({'source':str(p),'source_sha256':sha(p),'output':'source/management_package.h','output_sha256':sha(SRC/'management_package.h')})
platform=(TX/'source/platform.c').read_text()
def function(name):
    m=re.search(r'^(?:static )?[^\n;]+\b'+name+r'\([^\n]*\)\{',platform,re.M);assert m,name
    start=m.start();at=m.end();depth=1
    while depth:
        if platform[at]=='{':depth+=1
        if platform[at]=='}':depth-=1
        at+=1
    return platform[start:at]+'\n'
prefix=platform[platform.index('typedef struct{uint32_t type'):platform.index('static CPU_ENV environment;')]
prefix=prefix.replace('static unsigned found[2],extra_found[2];static CPU *cpu;static CONFIG *setup_config;','static unsigned found[2],extra_found[2];static CONFIG *setup_config;')
prefix=re.sub(r'^static GUID cpu_guid=.*\n','',prefix,flags=re.M)
prefix=prefix.replace('static SPAN all_images[4096];','')
prefix=prefix.replace('static HANDLE handles[4096],hii_handles[512];static UN image_count;','static HANDLE handles[4096],hii_handles[512];')
prefix+= 'static CPU_ENV environment;\nstatic uint8_t original_headers[2][0x108];static uint32_t original_pe[2];static int inventory_ready;\n'
selected=['span_ok','current_environment','access_range','header_matches','original_text','extra_identity','exact_entry_context','interface_inventory']
body=''.join(function(n)for n in selected)
body=body.replace('BSP_TPL_TRANSACTION_PREMISE=YES','BROWSER_BASELINE_NO_TRANSACTION=YES')
sites='''static int original_sites(void){for(unsigned i=0;i<12;i++){const PATCH *p=&expected_patches[i];uint8_t *at=images[p->module]+p->rva;
 if(!access_range((uintptr_t)at,p->length,0,0))return 0;
 if(p->pointer){if(u64(at)!=(uintptr_t)images[p->module]+p->old_rva)return 0;}
 else if(memcmp(at,p->bytes,p->length))return 0;}return 1;}
'''
inv=function('platform_inventory').replace('platform_inventory','baseline_inventory')
inv=inv.replace('||!bs->allocate_pages','').replace('||!bs->load_image','')
inv=inv.replace('return 0;image_count=0;','return 0;')
inv=inv.replace('all_images[image_count++]=(SPAN){(uintptr_t)li->image_base,li->image_size};','')
start=inv.index(' app_require_services();status=bs->locate_protocol(&cpu_guid')
end=inv.index(' void *existing=0;',start);inv=inv[:start]+inv[end:]
inv=inv.replace('!foreign_unchanged()','!current_environment()')
out=SRC/'inventory.c';out.write_text('/* Derived from frozen TX05 read-only inventory; no installer/allocator/provider payload. */\n#include "baseline.h"\n'+prefix+body+sites+inv+'''
int baseline_map(void){return refresh_map();}
int baseline_access(const void *p,UN bytes,int write){return current_environment()&&access_range((uintptr_t)p,bytes,write,0);}
int baseline_original_unchanged(void){
 if(!inventory_ready||!refresh_map()||!current_environment())return 0;
 for(unsigned i=0;i<2;i++)if(!header_matches(loaded[i],&expected_targets[i],0)||loaded[i]->image_base!=images[i]||!original_text(i)||memcmp(images[i]+original_pe[i],original_headers[i],0x108))return 0;
 return original_sites()&&extra_identity(0)&&extra_identity(1)&&access_range((uintptr_t)app_browser,16,0,0)&&u64(app_browser)==(uintptr_t)images[0]+0x20ee4;
}
void baseline_globals(const char *label){
 static const uint32_t rvas[]={0x83588,0x83468,0x930b0,0x93948,0x93028,0x83580};
 static const char *names[]={"NativeAppPtr","NativeStage","NativePagesPtr","NativeRecordsPtr","NativeExternalPtr","NativePendingReset"};
 app_log(label);app_log("\\r\\n");if(!inventory_ready||!refresh_map()||!current_environment()){app_result("native globals readable",0);return;}
 for(unsigned i=0;i<6;i++){uint8_t *at=images[0]+rvas[i];if(!access_range((uintptr_t)at,i==5?1:8,0,0)){app_result("native global readable",0);return;}app_number(names[i],i==5?*at:u64(at));}
}
''')
bindings.append({'source':str(TX/'source/platform.c'),'source_sha256':sha(TX/'source/platform.c'),'operation':'Only read-only inventory functions; original_sites uses copied expected_patches. Exclude transaction, P13 loader, allocation and attribute services.','output':'source/inventory.c','output_sha256':sha(out)})
(HERE/'source_derivation.json').write_text(json.dumps({'inputs':bindings,'note':'Transport/efi.h labels and callable setter declaration are adapted; copied input hashes above remain provenance, final build records final output hashes.'},indent=2)+'\n')
print('READONLY_SOURCE_SUBSET_CREATED')
