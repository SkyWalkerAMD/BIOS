"""Reviewable static derivative; frozen 04 and tested type27 DLL remain unchanged."""
from pathlib import Path
H=Path(__file__).resolve().parent;B=H.parent
s=(H/'observer.h').read_text().replace('NO_MAX_PATCHES 32u','NO_MAX_PATCHES 64u')
(H/'observer_static05.h').write_text(s)
for name in ['management.h','internal.h','package.c','publisher.c','bridge.c']:
 s=(B/'management_live04'/name).read_text().replace('MP_MAX_PATCHES 32U','MP_MAX_PATCHES 64U')
 (H/name.replace('.c','_static05.c')).write_text(s)
s=(H/'observer05.c').read_text()
s=s.replace('#include "observer.h"','#include "observer_static05.h"')
s=s.replace('#include "profile_windows.h"','#include "profile_windows.h"\n#include "../packaging05/layout.h"\n#include "static05.h"')
s=s.replace('provider_token,pubtoken;','provider_token,pubtoken,native_visit,visit_sequence;')
s=s.replace('uint8_t published,entering,pending_begin,pending_end;','uint8_t published,entering,pending_begin,pending_end,parsing;')
s=s.replace('q.session=s.provider_token;','q.session=s.native_visit;')
s=s.replace('if(kind==NO_LOOP){s.loops++;s.pending_begin=1;', 'if(kind==NO_LOOP){if(!s.loops){if(s.visit_sequence==UINT64_MAX){s.depth--;zero(f,sizeof(*f));return 0;}s.native_visit=++s.visit_sequence;}s.loops++;s.pending_begin=1;')
s=s.replace('if(FAILED(r)){s.loops--;s.depth--;zero(f,sizeof(*f));return 0;}f->begun=1;', 'if(r!=0){s.loops--;if(!s.loops)s.native_visit=0;s.depth--;zero(f,sizeof(*f));return 0;}f->begun=1;')
s=s.replace('if(!s.loops)s.provider_token=0;', 'if(!s.loops){s.provider_token=0;s.native_visit=0;}')
needle=' uint32_t bytes=which?174073:597466,size=which?2154496:909312;'
s=s.replace(needle,''' if(!which){return no_range((uintptr_t)m->loaded,sizeof(LOADED),NO_READ)&&m->loaded->image_base==(void*)m->base&&m->loaded->image_size==m->size&&fv_path(m->loaded->filepath,&m->ffs)&&i05_image_range(m->base,m->size)&&i05_layout_live(m->base,m->size);}
 uint32_t bytes=174073,size=2154496;''')
s=s.replace('if(m.size==909312&&fv_path(l->filepath,&tse_guid))','if(i05_layout_get()&&m.size==i05_layout_get()->image_size&&fv_path(l->filepath,&tse_guid))')
start=s.index('static int trampoline(');end=s.index('static int patches_live(',start)
s=s[:start]+'''ES EA no_prepare(const NO_INSTALL *i){
 const I05_LAYOUT*l=i05_layout_get();
 if(!l||!s.initialized||s.prepared||s.fault||s.ended||!tpl_application()||!refresh_map()||!no_range((uintptr_t)i,sizeof(*i),NO_READ)||i->revision!=NO_REVISION||i->size!=sizeof(*i)||i->patch_count!=l->patch_count||i->patch_count>NO_MAX_PATCHES||i->call_count>NO_MAX_CALLS||i->provider!=&w890_provider)return NO_DENIED;
 if(!no_range((uintptr_t)i->patches,i->patch_count*sizeof(NO_PATCH),NO_READ)||(i->call_count&&!no_range((uintptr_t)i->calls,i->call_count*sizeof(NO_CALL),NO_READ)))return NO_DENIED;
 if((uintptr_t)i->loop_trampoline!=s.tse.base+i05_layout_symbol("i05_original_loop",1)||(uintptr_t)i->send_trampoline!=s.tse.base+i05_layout_symbol("i05_original_send",1)||i->entry_trampoline!=(void*)(s.tse.base+0x6480)||i->management_bridge!=mp_callback||i->publish!=mp_native_publish||i->publisher!=i05_management_state())return NO_DENIED;
 for(unsigned k=0;k<i->patch_count;k++){const NO_PATCH*p=&i->patches[k];const I05_PATCH*q=&l->patches[k];if(p->module||p->rva!=q->rva||p->length!=q->length||p->reserved||!eq(p->original,q->original,p->length)||!eq(p->installed,q->installed,p->length))return NO_DENIED;}
 s.install=*i;s.patch_count=i->patch_count;s.call_count=i->call_count;cp(s.patches,i->patches,s.patch_count*sizeof(NO_PATCH));cp(s.calls,i->calls,s.call_count*sizeof(NO_CALL));
 if(!module_text(&s.tse,0,1)||!module_text(&s.setup,1,0))goto failed;
 for(unsigned k=0;k<s.call_count;k++)if(s.calls[k].address<s.tse.base+l->extension_rva+16||s.calls[k].address>=s.tse.base+s.tse.size-16||!no_range(s.calls[k].address-16,32,NO_READ|NO_EXEC)||!eq((void*)(s.calls[k].address-16),s.calls[k].window,32))goto failed;
 s.prepared=1;return 0;
failed:revoke();return NO_DENIED;
}
''' + s[end:]
# Expected synchronous Update notifications renew only the one genuine parser
# frame and its active parent frames. Any foreign HII mutation revokes all.
s=s.replace('if(handle==s.setup_hii&&s.changing&&s.pubtoken&&s.depth==1&&s.frames[0].kind==NO_COLD&&(kind==2||kind==8)&&!s.loops&&!s.sends)s.frames[0].epoch=s.epoch;',
'''if(handle==s.setup_hii&&s.changing&&s.pubtoken&&s.depth&&s.frames[s.depth-1].kind==NO_PREPARSE&&(kind==2||kind==8)&&s.parsing){for(unsigned i=0;i<s.depth;i++)s.frames[i].epoch=s.epoch;}''')
start=s.index('static int cold(void)');end=s.index('int EA no_publication_validate',start)
s=s[:start]+'''/* Only the private original-parser entry frame authorizes package mutation.
 * Original init changes two fixed fields in the embedded SPF; normalize those
 * exact native changes, never accept arbitrary descriptor data/owner booleans. */
static int cold(void){
 FRAME*f=top();if(!f||f->kind!=NO_PREPARSE||f->epoch!=s.epoch||!s.parsing||s.fault||s.ended||!no_range(s.tse.base+0xafb00,0x600,NO_READ)||!no_range(s.tse.base+0xbaa00,0x200,NO_READ)||readg(0xafdd0)||readg(0xafde8)||u32((void*)(s.tse.base+0xafe00)))return 0;
 uintptr_t raw=readg(0xbabc0);if(!no_range(raw,0xf245c,NO_READ)||u32((void*)raw)!=0x46505324||u32((void*)(raw+0x44))!=0xf245c||u16((void*)(raw+0x54))!=0x15||u32((void*)(raw+0xee040))!=7)return 0;
 static const uint8_t h[32]={0xe9,0xb4,0x79,0x9c,0x79,0xe2,0x3d,0x75,0xb3,0x9a,0x12,0x30,0x66,0xc6,0xab,0x80,0xed,0x3f,0x91,0x76,0xdf,0xc5,0x7a,0x50,0x72,0x79,0x68,0xc5,0xb1,0xec,0x08,0xf3};
 cp(s.package,(void*)raw,0xf245c);s.package[0x54]=4;s.package[0xee040]=0;return digest(s.package,0xf245c,h);
}
''' + s[end:]
# Publishing uses s.package as export scratch, so cold() must not clobber it
# while mp_export / export_forms is retaining it. A separate exact SPF buffer.
s=s.replace('uint8_t package[PKG_CAP],forms', 'uint8_t spf_scratch[0xf245c];uint8_t package[PKG_CAP],forms')
s=s.replace('cp(s.package,(void*)raw,0xf245c);s.package[0x54]=4;s.package[0xee040]=0;return digest(s.package,0xf245c,h);','cp(s.spf_scratch,(void*)raw,0xf245c);s.spf_scratch[0x54]=4;s.spf_scratch[0xee040]=0;return digest(s.spf_scratch,0xf245c,h);')
s+='''
/* Called by a five-byte JMP from the original parser prologue. RETADDR is
 * therefore the original AMITSE caller, not a caller-supplied address. */
API ES EA i05_preparse(void){
 uintptr_t caller=RETADDR,stack=(uintptr_t)__builtin_frame_address(0);
 if(!i05_parser_caller(caller))return NO_DENIED;
 if(i05_services()!=0||s.parsing||!identity_live(1))i05_failure();
 static const uint32_t callers[]={0x18e46,0x45367,0x7c487,0x82265,0x885cb};unsigned matches=0;
 for(unsigned i=0;i<5;i++)if(caller==s.tse.base+callers[i])matches++;
 if(matches!=1||s.depth>=NO_MAX_DEPTH)return NO_DENIED;
 FRAME*f=push(NO_PREPARSE,caller,stack);if(!f)return NO_DENIED;s.parsing=1;
 if(!s.published){
  if(!cold())goto failed;s.pubtoken=++s.sequence;s.changing=1;
  ES r=s.install.publish(s.install.publisher,s.pubtoken);s.changing=0;s.pubtoken=0;
  if(r!=0||!s.published)goto failed;
 }else{
  UN n=0;cp(s.scratch,s.forms,s.forms_bytes);
  if(!export_forms(s.setup_hii,s.forms,&n)||n!=s.forms_bytes||!eq(s.forms,s.scratch,n))goto failed;
 }
 if(!identity_live(1))goto failed;
 uintptr_t native=s.tse.base+i05_layout_symbol("i05_original_parser",1);
 if(native==s.tse.base||!no_range(native,10,NO_READ|NO_EXEC))goto failed;
 ES r=((ES(EA*)(void))native)();s.parsing=0;pop(f);return r;
failed:s.parsing=0;s.pubtoken=0;s.changing=0;revoke();pop(f);i05_failure();
}
'''
s+='\n#include "../navigation05/visit/form_descriptor.inc"\n'
(H/'observer_static05.c').write_text(s)

s=(B/'management_live04/identity.c').read_text().replace('#include "internal.h"','#include "internal.h"\n#include "static05.h"\n#include "../packaging05/layout.h"')
needle=' static const uint32_t image_sizes[2]'
at=s.index(needle)
s=s[:at]+''' if(index==1)return i05_image_range((uintptr_t)expected,size)&&i05_layout_live((uintptr_t)expected,size);
''' + s[at:]
s=s.replace('memcmp(base+p->rva,p->original,p->length)', 'memcmp(base+p->rva,p->module?p->original:p->installed,p->length)')
# mp_bind's caller data cannot establish a new overlay set; exact immutable
# layout controls every AMITSE patch. Setup remains strictly original.
s=s.replace('  s->patches[i]=*p;', '''  const I05_LAYOUT*l=i05_layout_get();if(!l||p->module||i>=l->patch_count||l->patch_count!=b->patch_count||p->rva!=l->patches[i].rva||p->length!=l->patches[i].length||memcmp(p->original,l->patches[i].original,p->length)||memcmp(p->installed,l->patches[i].installed,p->length))goto invalid;
  s->patches[i]=*p;''')
(H/'identity_static05.c').write_text(s)
s=(H/'bridge_static05.c').read_text()
s=s.replace('#include "internal.h"','#include "internal.h"\nextern int EA i05_profile_gate(CONFIG*,UN,uint16_t,uint8_t,void*,UN*,void*);')
start=s.index('__attribute__((noinline))');end=s.index('int mp_management_scope',start)
s=s[:start]+'''extern ES EA mp_call_provider(UN,uint16_t,uint8_t,void*,UN*);
extern uint8_t mp_call_provider_return[];
int mp_provider_caller(void*address){return address==mp_call_provider_return;}
''' + s[end:]
s=s.replace('status=call_provider(', 'status=mp_call_provider(')
s=s.replace('  return s->original_callback(this,action,question,type,value,request);','  if(!i05_profile_gate(this,action,question,type,value,request,caller))return ERR(15);\n  return s->original_callback(this,action,question,type,value,request);')
(H/'bridge_static05.c').write_text(s)
print('static derivatives generated')
