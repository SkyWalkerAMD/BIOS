"""Create a separate diagnostic-only TCG fixture; never edit the P14 lab."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;D04=HERE.parent;OLD=D04/'provider14_ovmf_lab'
SNAP=D04/'diagnostic09_independent_review/provider_revisions/d15438fde33bf0fa'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(SNAP/'build/AiTweakerSplitProvider15.UNSIGNED.local.efi')=='d15438fde33bf0fada0a33f9f62a9ca8ff72cf21bb924ceaeca0bc75a0b0a5cf'
assert not (HERE/'diagnostic_ui.c').exists()
source=(OLD/'persist_ui.c').read_text(encoding='utf8')
prefix=source[source.index('#include "split_owner.h"'):source.index('static GUID phase_guid')]
paths=source[source.index('typedef struct{uint8_t type'):source.index('typedef struct{uint64_t magic')]
helpers=source[source.index('void *memcpy'):source.index('static void record_check')].replace('P14_UI_OVMF','P15_DIAGNOSTIC_OVMF')
setup=source[source.index(' LOADED *self=0'):source.index(' uint8_t digest[32];\n if(boot==1)')]
setup=setup.replace('prepare_split_fixture();install_debug_fixture();','prepare_split_fixture();\n DIAG09_REGION *diag=(void *)((uint8_t *)split_state+DIAG09_STATE_OFFSET);diag->magic=DIAG09_MAGIC;diag->revision=1;diag->bytes=sizeof(*diag);\n install_debug_fixture();')
ending=source[source.index(' check(st->rt->get_variable==original_get'):]
globals_text=r'''
static C16 credential_name[]=L"AiTweakerPassword1904";
static ST *st;static GATE_PROVIDER *provider;static unsigned checks,operation;
static const char *step_name;static uint8_t *tse_base,*setup_base;
static SPLIT_CONTEXT split_context;static SPLIT_STATE *split_state;
#include "diagnostic09.h"
#include "fixture_extra.inc"
'''
body=r'''
static uint64_t EA browser_body(void){
 check(provider->query(provider)==3,"real native wrapper owns locked session");
 trace("STEP_BEGIN ");trace(step_name);trace("\n");
 BROWSER_ACTION_REQUEST request=0;ES result;
 if(operation==0){
  result=form_browser->send_form(form_browser,&management_hii,1,&management_formset,1,0,&request);
  check(!result&&request==0,"real OVMF independent form returns NONE after Verify and ESC");
 }else{
  result=management_config->callback(management_config,0,0xffe2,0,0,&request);
  check(result==ERR(15)&&request==0,"actual independent Verify remains denied without credential");
 }
 check(provider->query(provider)==3,"unconfigured acknowledgement never grants session");
 trace("STEP_RETURN ");trace(step_name);trace(" ");hex(result);trace("\n");return 0x190411;
}
static void run_step(unsigned op,const char *name){
 operation=op;step_name=name;uint64_t(EA *loop)(void)=(void *)(tse_base+0xe1b8);
 uint64_t hits=debug_hits;debug_arm();check(loop()==0x190411,"native wrapper preserves declared body-stub result");debug_disarm();
 check(debug_hits==hits+1,"exactly one TCG body redirection per session");
 check(!split_state->ui_head&&!split_state->save_head,"real guard popped detached chains");
 check(provider->query(provider)==1,"outer end returns locked without owner");
 validate_text_identity();trace("STEP_DONE ");trace(name);trace("\n");
}
ES EA efi_main(HANDLE image,ST *table){
 if(!tcg())return ERR(3);st=table;trace("P15_DIAGNOSTIC_OVMF_BEGIN\n");
 UN initial=0;check(st->rt->get_variable(credential_name,&credential_guid,0,&initial,0)==ERR(14),"fresh real OVMF has no test credential");
'''
steps=r'''
 run_step(0,"form_verify_one");
 check(diag->request_count==1&&diag->prompt_count==1&&diag->ack_count==1&&!(diag->flags&DIAG09_FLAG_REQUEST_PENDING),"first real key acknowledgement and exact diagnostic counters");
 run_step(1,"direct_verify_two");
 check(diag->request_count==2&&diag->prompt_count==2&&diag->ack_count==2,"second request and ACK have distinct serial");
 /* Deliberate mutations of the private owned DIAGNOSTIC region only. They do
  * not alter grant/credential or OEM objects and never leave this local lab. */
 diag->flags|=DIAG09_FLAG_DROPPED_WRITER;
 run_step(2,"sticky_trace_unavailable");
 check(diag->request_count==3&&diag->prompt_count==3&&diag->ack_count==3,"sticky diagnostic loss preserves original denied UI and ACK");
 diag->magic^=1;
 run_step(3,"invalid_header_unavailable");
 check(diag->request_count==3&&diag->prompt_count==3&&diag->ack_count==3,"invalid diagnostic storage adds no counter write");
 diag->magic^=1;
 UN final_size=0;check(st->rt->get_variable(credential_name,&credential_guid,0,&final_size,0)==ERR(14),"credential remains absent after all diagnostic-only prompts");
'''
text='/* LOCAL QEMU TCG ONLY. Actual P15 diagnostics and real OVMF services; ASUS body is replaced by an explicit #DB fixture. No credential creation or hardware support. */\n'+prefix+paths+globals_text+helpers+body+setup+steps+ending
(HERE/'diagnostic_ui.c').write_text(text,encoding='utf8',newline='\n')
(HERE/'fixture_extra.inc').write_text((OLD/'fixture_extra.inc').read_text().replace('P14','P15'),encoding='utf8',newline='\n')
inputs=HERE/'inputs';(inputs/'source').mkdir(parents=True)
for p in (SNAP/'source').iterdir():(inputs/'source'/p.name).write_bytes(p.read_bytes())
(inputs/'provider.efi').write_bytes((SNAP/'build/AiTweakerSplitProvider15.UNSIGNED.local.efi').read_bytes())
(inputs/'provider-build.json').write_bytes((SNAP/'build/build.json').read_bytes())
reference=HERE/'reference';reference.mkdir()
for p in (OLD/'reference').iterdir():
 if p.is_file():(reference/p.name).write_bytes(p.read_bytes())
(HERE/'origins.json').write_text(json.dumps({'provider_sha256':sha(inputs/'provider.efi'),'old_p14_source_sha256':sha(OLD/'persist_ui.c'),'old_extra_sha256':sha(OLD/'fixture_extra.inc'),'new_source_sha256':sha(HERE/'diagnostic_ui.c'),'new_extra_sha256':sha(HERE/'fixture_extra.inc'),'prepare_sha256':sha(Path(__file__)),'scope':'Separate diagnostic-only fixture. Actual P15 entry/owner/HII/UI/storage and OVMF keyboard/graphics execute. OEM browser body is an explicit TCG substitution, not native ASUS behavior. No password creation or variable setter in this fixture.'},indent=2)+'\n')
print('Prepared separate P15 diagnostic-only OVMF fixture')
