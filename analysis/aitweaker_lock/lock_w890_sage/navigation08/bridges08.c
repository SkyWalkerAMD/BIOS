#include "../navigation05/bridges.h"
#include "../password/w890_policy.h"
#include "../navigation/input_registry_data.h"
#include "../navigation05/hotkeys_data.h"
int EA no_describe_form_callback(NO_TICKET*,uintptr_t,uintptr_t,WG_SNAPSHOT*);
static NO_IDENTITY binding;static unsigned ready,control_busy;
static int recovery_services(void);
static BS saved_bs;static BS *boot;static INPUT saved_in;static TEXTOUT saved_out;static INPUT *input;static TEXTOUT *output;
uintptr_t n05_first_resume,n05_form_open_trampoline;
static void cp(void*d,const void*s,UN n){uint8_t*x=d;const uint8_t*y=s;while(n--)*x++=*y++;}
static int eq(const void*a,const void*b,UN n){const uint8_t*x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static uint64_t p64(uintptr_t p){uint64_t v;cp(&v,(void*)p,8);return v;}
static uint32_t p32(uintptr_t p){uint32_t v;cp(&v,(void*)p,4);return v;}
static uint16_t p16(uintptr_t p){uint16_t v;cp(&v,(void*)p,2);return v;}
static int rng(uintptr_t p,UN n){return p&&no_range(p,n,NO_READ);}
static int live(NO_IDENTITY*id,WG_SNAPSHOT*s){return ready&&no_identity(id)&&!id->fault&&!id->ended&&id->loop_depth&&id->tse_base==binding.tse_base&&id->setup_base==binding.setup_base&&id->hii==binding.hii&&no_observe(0,WG_FIRST,0,0,s);}
static int event(uintptr_t e){return rng(e,0x30)&&(p16(e+8)==1||p16(e+8)==2);}
static int app_event(uintptr_t e){return rng(e,0x30)&&p16(e+8)>=1&&p16(e+8)<=3;}
static int registry(uintptr_t control,uintptr_t *target){if(!rng(control,0x60))return 0;uint64_t table=p64(control);uint16_t type=p16(control+0x34);
 for(unsigned i=0;i<sizeof(wi_types)/sizeof(wi_types[0]);i++)if(type==wi_types[i].type&&table==binding.tse_base+wi_types[i].table){
  if(!rng(table+0x20,8)||p64(table+0x20)!=(uintptr_t)n05_native_control_input)return 0;*target=binding.tse_base+wi_types[i].input;return 1;}
 return 0;}
static int menu_scope(WG_SNAPSHOT*s,uintptr_t c){
 if(!rng(c,0x98)||p64(c)!=binding.tse_base+0x95680||p16(c+0x34)!=14||p64(c+8)!=(uintptr_t)n05_menu||p64(c+0x18)!=binding.tse_base+0x94758||p64(binding.tse_base+0x94408)!=(uintptr_t)n05_menu)return 0;
 uintptr_t f=p64(c+0x10);if(!rng(f,0x50)||p32(f+0x20)!=4)return 0;uint32_t nf=p32(s->page+0x4c),nc=p32(f+0x3c);uintptr_t fa=p64(s->page+0x50),ca=p64(f+0x48);if(nf>64||nc>4096||!rng(fa,8u*nf)||!rng(ca,8u*nc))return 0;
 unsigned fm=0,cm=0;for(unsigned i=0;i<nf;i++)if(p64(fa+i*8u)==f)fm++;for(unsigned i=0;i<nc;i++)if(p64(ca+i*8u)==c)cm++;return fm==1&&cm==1;
}
static int silent_control(uintptr_t c,uintptr_t e,WG_SNAPSHOT *out){
 if(!no_observe(0,WG_CONTROL_INPUT,c,e,out))return 0;int kind=w890_classify_control(out->formset,out->form,out->ifr,out->ifr_size);
 if(kind==W890_UNPROTECTED)return 1;if(kind!=W890_PROTECTED)return 0;uint32_t f=w890_provider.query(&w890_provider);return(f&3)==3&&!(f&112)&&(f&12);
}
ES EA n05_bridges_bind(void){
 if(ready||!no_identity(&binding)||binding.fault||binding.ended||binding.loop_depth||!binding.st||!rng((uintptr_t)binding.st,sizeof(ST)))return NO_DENIED;
 BS*bs=binding.st->bs;boot=bs;input=binding.st->in;output=binding.st->out;
 if(!rng((uintptr_t)bs,sizeof(BS))||!rng((uintptr_t)input,sizeof(INPUT))||!rng((uintptr_t)output,sizeof(TEXTOUT)))return NO_DENIED;
 saved_bs=*bs;saved_in=*input;saved_out=*output;
 if(!saved_bs.wait||!saved_bs.raise_tpl||!saved_bs.restore_tpl||!saved_in.read||!saved_in.wait||!saved_out.out||!no_range((uintptr_t)saved_bs.wait,1,NO_EXEC)||!no_range((uintptr_t)saved_in.read,1,NO_EXEC)||!no_range((uintptr_t)saved_out.out,1,NO_EXEC))return NO_DENIED;
 n05_first_resume=binding.tse_base+0x1946b;ready=1;return 0;
}
ES EA n05_native_render(void *page){NO_IDENTITY id;WG_SNAPSHOT s;
 if(!live(&id,&s)||!no_observe(0,WG_RENDER,(uintptr_t)page,0,&s))return 0;
 if(n05_check(WG_RENDER,(uintptr_t)page,0)){n05_fallback_main();return 0;}
 return((ES(EA*)(void*))(binding.tse_base+0x2372c))(page);
}
ES EA n05_native_page_input(void *page,void *ev,void *aux){NO_IDENTITY id;WG_SNAPSHOT s;
 if(!event((uintptr_t)ev)||!live(&id,&s)||s.page!=(uintptr_t)page)return 0;
 if(n05_check(WG_PAGE_INPUT,(uintptr_t)page,(uintptr_t)ev)){n05_fallback_main();return 0;}
 return((ES(EA*)(void*,void*,void*))(binding.tse_base+0x238bc))(page,ev,aux);
}
ES EA n05_native_frame_input(void *frame,void *ev){NO_IDENTITY id;WG_SNAPSHOT s;
 if(!event((uintptr_t)ev)||!live(&id,&s)||!rng((uintptr_t)frame,0x50))return 0;
 uint32_t n=p32(s.page+0x4c);uintptr_t a=p64(s.page+0x50);if(n>64||!rng(a,n*8u))return 0;unsigned matches=0;
 for(unsigned i=0;i<n;i++)if(p64(a+i*8u)==(uintptr_t)frame)matches++;if(matches!=1)return 0;
 uint32_t nc=p32((uintptr_t)frame+0x3c);uintptr_t ca=p64((uintptr_t)frame+0x48);if(nc>4096||(nc&&!rng(ca,nc*8u)))return 0;
 for(unsigned i=0;i<nc;i++){uintptr_t target;if(!registry(p64(ca+i*8u),&target))return 0;}
 return((ES(EA*)(void*,void*))(binding.tse_base+0x21ef4))(frame,ev);
}
ES EA n05_native_control_input(void *object,void *ev){
 if(control_busy)return 0;control_busy=1;ES result=0;NO_IDENTITY id;WG_SNAPSHOT source,a,b;uintptr_t c=(uintptr_t)object,e=(uintptr_t)ev,target=0;
 if(!event(e)||!live(&id,&source)||!registry(c,&target))goto done;
 if(p16(c+0x34)==14){if(!menu_scope(&source,c))goto done;}
 else{
  if(p16(e+8)==1&&n05_check(WG_CONTROL_INPUT,c,e))goto done;
  if(!silent_control(c,e,&a)||!silent_control(c,e,&b)||!eq(&a,&b,sizeof(a)))goto done;
 }
 if(!live(&id,&b)||source.application!=b.application||source.page!=b.page||!registry(c,&target))goto done;
 if(p16(c+0x34)==14&&!menu_scope(&b,c))goto done;
 result=((ES(EA*)(void*,void*))target)(object,ev);
done:control_busy=0;return result; /* zero consumes a refusal at Frame AND Page */
}
static int extra_scope(WG_SNAPSHOT*s,uintptr_t o,int mouse){
 if(!rng(o,mouse?0x38:0x30)||p64(o)!=binding.tse_base+(mouse?0x93e70:0x93ea0)||p64(o+0x10)!=s->application||p64(o+0x18))return 0;
 uintptr_t a=s->application;uint64_t n=p64(a+(mouse?0x48:0x38));uintptr_t arr=p64(a+(mouse?0x50:0x40));if(n>64||(n&&!rng(arr,n*8)))return 0;
 unsigned found=0,known=0;for(UN i=0;i<n;i++)if(p64(arr+i*8)==o)found++;if(found!=1)return 0;
 if(mouse){for(unsigned i=0;i<7;i++)if(eq((void*)(o+0x20),extra_mouse[i].rect,16)&&p32(o+0x30)==extra_mouse[i].flags&&p64(o+8)==(extra_mouse[i].callback?binding.tse_base+extra_mouse[i].callback:0))known++;}
 else{for(unsigned i=0;i<9;i++)if(p32(o+0x20)==extra_keys[i].key&&p32(o+0x24)==extra_keys[i].mod&&p32(o+0x28)==extra_keys[i].flags&&p64(o+8)==binding.tse_base+extra_keys[i].callback)known++;}
 return known==1&&p64(binding.tse_base+(mouse?0x93e90:0x93ec0))==(uintptr_t)(mouse?n05_native_alt_input:n05_native_extra_input);
}
ES EA n05_native_extra_input(void *object,void *ev){NO_IDENTITY id;WG_SNAPSHOT s;uintptr_t o=(uintptr_t)object,e=(uintptr_t)ev;
 if(!live(&id,&s)||!app_event(e)||!extra_scope(&s,o,0))return 0;
 if(p16(e+8)!=1||!eq((void*)(e+0xc),(void*)(o+0x20),4))return NO_UNSUPPORTED;
 if(n05_check(WG_PAGE_INPUT,s.page,e))return 0;
 return((ES(EA*)(void*,void*))(binding.tse_base+0x275d0))(object,ev);
}
ES EA n05_native_alt_input(void *object,void *ev){NO_IDENTITY id;WG_SNAPSHOT s;uintptr_t o=(uintptr_t)object,e=(uintptr_t)ev;
 if(!live(&id,&s)||!app_event(e)||!extra_scope(&s,o,1))return 0;if(p16(e+8)!=3)return NO_UNSUPPORTED;
 if(n05_check(WG_PAGE_INPUT,s.page,e))return 0;
 return((ES(EA*)(void*,void*))(binding.tse_base+0x27464))(object,ev);
}
ES EA n05_native_app_input(void *app,void *ev){NO_IDENTITY id;WG_SNAPSHOT s;uintptr_t a=(uintptr_t)app;
 if(!live(&id,&s)||s.application!=a||!app_event((uintptr_t)ev)||!rng(a,0x60))return 0;
 if(n05_check(WG_PAGE_INPUT,s.page,(uintptr_t)ev)){n05_fallback_main();return 0;}
 for(unsigned mouse=0;mouse<2;mouse++){uint64_t n=p64(a+(mouse?0x48:0x38));uintptr_t array=p64(a+(mouse?0x50:0x40));if(n>64||(n&&!rng(array,n*8)))return 0;
  for(UN i=0;i<n;i++)if(!extra_scope(&s,p64(array+i*8),(int)mouse))return 0;}
 return((ES(EA*)(void*,void*))(binding.tse_base+0x1d9c8))(app,ev);
}
/* n08: native 3F414 lifecycle callbacks remain original and unpatched.
 * Page-selection/render/input protection is independent of the original
 * FORM_OPEN/FORM_CLOSE, original pending HII updates and teardown bookkeeping. No fabricated callback
 * status, ActionRequest or global lifecycle permission is introduced. */
static int recovery_services(void){
 if(!ready||!rng((uintptr_t)binding.st,sizeof(ST))||binding.st->bs!=boot||binding.st->in!=input||binding.st->out!=output||!rng((uintptr_t)boot,sizeof(BS))||!rng((uintptr_t)input,sizeof(INPUT))||!rng((uintptr_t)output,sizeof(TEXTOUT)))return 0;
 BS*bs=binding.st->bs;return bs->wait==saved_bs.wait&&bs->raise_tpl==saved_bs.raise_tpl&&bs->restore_tpl==saved_bs.restore_tpl&&input->wait==saved_in.wait&&input->read==saved_in.read&&output->out==saved_out.out&&no_range((uintptr_t)saved_bs.wait,1,NO_EXEC)&&no_range((uintptr_t)saved_bs.raise_tpl,1,NO_EXEC)&&no_range((uintptr_t)saved_bs.restore_tpl,1,NO_EXEC)&&no_range((uintptr_t)saved_in.read,1,NO_EXEC)&&no_range((uintptr_t)saved_out.out,1,NO_EXEC);
}
uint32_t EA n05_recovery_poll(void *original_app){
 if(!recovery_services())return 2;UN old=saved_bs.raise_tpl(31);if(!recovery_services())return 2;saved_bs.restore_tpl(old);if(old!=4||!recovery_services())return 2;
 EVENT e=saved_in.wait;UN index=~(UN)0;ES r=saved_bs.wait(1,&e,&index);
 if(r!=0||index||!recovery_services())return 2;KEY key;if(saved_in.read(input,&key)!=0||!recovery_services())return 2;
 if(key.ch=='r'||key.ch=='R'){WG_SNAPSHOT s;if(no_observe(0,WG_FIRST,(uintptr_t)original_app,0,&s)&&n05_fallback_main()==N05_MAIN&&no_observe(0,WG_FIRST,(uintptr_t)original_app,0,&s)&&s.form==0x2712)return 1;}
 return 0;
}
void EA n05_first_dispatch(void *original_app){
 WG_SNAPSHOT s;uint32_t r=n05_first();if((r==N05_CONTINUE||r==N05_MAIN)&&no_observe(0,WG_FIRST,(uintptr_t)original_app,0,&s))return;
 if(!recovery_services())n05_recovery_terminal();
 UN tpl=saved_bs.raise_tpl(31);if(!recovery_services())n05_recovery_terminal();saved_bs.restore_tpl(tpl);if(tpl!=4||!recovery_services())n05_recovery_terminal();
 if(saved_out.out(output,U("\r\nAi Tweaker protection: Setup identity could not be verified.\r\nProtected Setup execution is stopped.\r\nPress R to retry Main. Otherwise restart through the management console.\r\n"))!=0)n05_recovery_terminal();
 for(;;){r=n05_recovery_poll(original_app);if(r==1)return;if(r==2)n05_recovery_terminal();}
}
