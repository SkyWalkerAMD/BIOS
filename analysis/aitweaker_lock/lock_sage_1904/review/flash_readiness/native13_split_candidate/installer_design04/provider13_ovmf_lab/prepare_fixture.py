"""Create this separate test fixture from the preserved P12 reference once."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
READY=HERE.parents[2]
OLD=READY/'native_provider12_ui_simulation'
source=(OLD/'persist_ui.c').read_text(encoding='utf8')
assert not (HERE/'persist_ui.c').exists()
source=source.replace('#include "provider.h"','#include "split_owner.h"\n#include "split_profile.h"\n#include "management_package.h"')
source=source.replace('static GUID provider_guid={0xf29d11ab,0xc12a,0x455a,{0x95,0xd3,0x9a,0x8e,0xcf,0x04,0x5c,0x04}};',
                      'static GUID provider_guid={0x87e3c6fa,0x11fb,0x4e77,{0xaf,0x2d,0xea,0x50,0xb6,0x40,0xfa,0x13}};')
source=source.replace('static uint8_t *tse_base;','static uint8_t *tse_base,*setup_base;\nstatic SPLIT_CONTEXT split_context;\nstatic SPLIT_STATE *split_state;\n#include "fixture_extra.inc"')
source=source.replace('static uint64_t EA browser_body(void){','static uint64_t EA browser_body(void){')
source=source.replace(' if(operation==0||operation==3)result=provider->manage(provider,0);\n else if(operation==7)result=provider->manage(provider,1);\n else if(operation!=8)result=provider->request(provider);',
                      ' if(operation!=8){BROWSER_ACTION_REQUEST request=~0ULL;uint16_t id=(operation==0||operation==3)?0xffe0:operation==7?0xffe1:0xffe2;result=management_config->callback(management_config,0,id,0,0,&request);check(request==0,"actual independent HII callback sets request NONE");}')
source=source.replace(' check(loop()==0x190411,"native wrapper preserves stub browser result");\n check(*(uint64_t *)(tse_base+TSE_CONTEXT_RVA)==0,"real native wrapper popped context");',
                      ' uint64_t hits=debug_hits;debug_arm();check(loop()==0x190411,"native wrapper preserves declared body-stub result");debug_disarm();check(debug_hits==hits+1,"exactly one TCG debug redirection per owned session");\n check(split_state->ui_head==0&&split_state->save_head==0,"real split guard popped both detached chains");')
begin=source.index(' check(*(uint64_t *)(tse_base+TSE_CONTEXT_RVA)==0,"native context initially empty");')
end=source.index(' buffer=read_file(root,U("\\\\PROVIDER.EFI")',begin)
source=source[:begin]+''' check(!st->bs->handle_protocol(setup,&loaded_guid,(void **)&li)&&li&&li->image_size==SETUP_IMAGE_BYTES,"relocated Setup original size valid");setup_base=li->image_base;
 prepare_split_fixture();install_debug_fixture();
'''+source[end:]
needle='check(!st->bs->start_image(driver,0,0),"actual provider entry starts");'
source=source.replace(needle,'check(!st->bs->handle_protocol(driver,&loaded_guid,(void **)&li)&&li,"provider LoadedImage available");li->options_size=sizeof(split_context);li->options=&split_context;'+needle)
needle='check(provider->query(provider)==1,"cold provider starts locked without owner");'
source=source.replace(needle,needle+'locate_management();check(management_config->callback(management_config,0,0xffe2,0,0,0)==ERR(15),"management callback rejects no-owner invocation");')
source=source.replace(' UN n=0,key=0,desc=0;', ' uninstall_debug_fixture();check(split_state->phase==1,"split state stays ARMED before actual EBS");\n UN n=0,key=0,desc=0;')
source=source.replace('check(provider->query(provider)==64,"real EBS permanently revokes provider");','check(provider->query(provider)==64,"real EBS permanently revokes provider");check(split_state->phase==3,"actual EBS retires split state to ENDED");')
source=source.replace('PERSIST_UI_OVMF','P13_UI_OVMF')
source=source.replace('/* TCG-only two-process persistence fixture.', '/* TCG-only two-process persistence fixture derived from P12. Read fixture_extra.inc.\n * OEM text remains exact except the declared twelve detours; #DB substitutes execution.\n * Historical description below is superseded for P13:\n * TCG-only two-process persistence fixture.')
(HERE/'persist_ui.c').write_text(source,encoding='utf8',newline='\n')
(HERE/'reference_origins.json').write_text(json.dumps({'reference_path':str(OLD/'persist_ui.c'),
 'reference_sha256':hashlib.sha256((OLD/'persist_ui.c').read_bytes()).hexdigest(),
 'old_source_unchanged':True,'scope':'Separate local fixture only; frozen provider files are read-only'},indent=2)+'\n',encoding='utf8')
print('Created P13 fixture source in owned lab only')
