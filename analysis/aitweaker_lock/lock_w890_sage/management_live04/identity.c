#include "internal.h"
MP_STATE *mp_current;
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID config_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static const GUID module_guids[2]={{0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}},
 {0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}}};
static const uint8_t text_sha[2][32]={
 {0x49,0xad,0x95,0xff,0x56,0x45,0x19,0xfd,0xdf,0x96,0x62,0x71,0xe9,0x78,0x01,0x6a,0x5b,0xc5,0x18,0xa4,0x88,0xb3,0xb6,0x12,0xbd,0xc7,0x93,0xa0,0xc7,0x35,0xb1,0xd0},
 {0xe0,0xb8,0x09,0x4c,0x48,0x2a,0x64,0x7d,0x71,0x96,0xd1,0x3a,0xa3,0xb0,0x59,0x90,0xd4,0x85,0x6d,0xc3,0x5d,0xe8,0xae,0xe1,0x03,0xb9,0xf9,0x35,0xfe,0x35,0xd9,0x58}};
static uint16_t u16(const uint8_t*p){return p[0]|((uint16_t)p[1]<<8);}
static int method(const void*p){return p&&w890_memory_present(p,1,0);}
int mp_live(MP_STATE*s){
 if(s!=mp_current||!w890_memory_present(s,sizeof(*s),0)||s->revision!=MP_REVISION||s->ended||w890_runtime_ended)return 0;
 MP_BINDING*b=&s->binding;
 if(!w890_memory_present(b->st,sizeof(*b->st),0)||b->st->bs!=s->pinned_bs||!w890_memory_present(b->st->bs,sizeof(BS),0)||
  !w890_memory_present(b->database,sizeof(HII),0)||!w890_memory_present(b->strings,sizeof(STRINGS),0)||!w890_memory_present(b->config,sizeof(CONFIG),0))return 0;
 void*methods[10]={(void*)b->st->bs->handle_protocol,(void*)b->st->bs->allocate_pool,(void*)b->st->bs->free_pool,
  (void*)b->database->get_driver,(void*)b->database->export_list,(void*)b->database->update_list,(void*)b->strings->new_string,
  b->strings->get_string,(void*)b->strings->set_string,(void*)b->strings->languages};
 for(unsigned i=0;i<10;i++)if(methods[i]!=s->service_methods[i]||!method(methods[i]))return 0;
 return method((void*)s->authority.window_valid)&&method((void*)s->authority.publication_finished)&&method((void*)s->authority.restoration_finished)&&
  method((void*)s->authority.management_enter)&&method((void*)s->authority.management_valid)&&method((void*)s->authority.management_leave);
}
int mp_window(MP_STATE*s,uint64_t ticket){
 return ticket&&mp_live(s)&&method((void*)s->authority.window_valid)&&s->authority.window_valid(s->authority.context,ticket)&&mp_live(s);
}
static int filepath(void*path,unsigned index){
 const uint8_t*p=path;unsigned count=0;
 for(UN at=0;at+4<=1024;){
  if(!w890_memory_present(p+at,4,0))return 0;UN n=u16(p+at+2);if(n<4||n>1024-at||!w890_memory_present(p+at,n,0))return 0;
  if(p[at]==0x7f)return p[at+1]==0xff&&n==4&&count==1;
  if(p[at]==4&&p[at+1]==6){if(n!=20||++count!=1||memcmp(p+at+4,&module_guids[index],16))return 0;}at+=n;
 }return 0;
}
static int module(MP_STATE*s,HANDLE handle,void*expected,UN size,unsigned index){
 LOADED*li=0;ES status=s->binding.st->bs->handle_protocol(handle,&loaded_guid,(void**)&li);
 if(!mp_live(s)||FAILED(status)||!w890_memory_present(li,sizeof(*li),0)||li->revision!=0x1000||li->image_base!=expected||li->image_size!=size||!filepath(li->filepath,index))return 0;
 static const uint32_t image_sizes[2]={2154496,909312},entry[2]={4816,25728},text_size[2]={174073,597466};
 const uint8_t*p=expected;if(size!=image_sizes[index]||!w890_memory_present(p,4096,0)||u16(p)!=0x5a4d)return 0;
 UN pe=mp_u32(p+0x3c);if(pe>4096-24||mp_u32(p+pe)!=0x4550||u16(p+pe+4)!=0x8664)return 0;
 UN opt=pe+24;unsigned sections=u16(p+pe+6),os=u16(p+pe+20);
 if(!sections||sections>96||os<0x70||os>4096-opt||u16(p+opt)!=0x20b||mp_u32(p+opt+16)!=entry[index]||mp_u32(p+opt+56)!=size)return 0;
 UN table=opt+os;if(sections>(4096-table)/40)return 0;unsigned found=0;
 for(unsigned i=0;i<sections;i++){const uint8_t*h=p+table+i*40;if(!memcmp(h,".text\0\0\0",8)){if(++found!=1||mp_u32(h+8)!=text_size[index]||mp_u32(h+12)!=4096)return 0;}}
 if(found!=1||!w890_memory_present(p+4096,text_size[index],0))return 0;
 memcpy(s->text_scratch,p+4096,text_size[index]);
 for(unsigned i=0;i<s->patch_count;i++){MP_PATCH*q=&s->patches[i];if(q->module!=1-index)continue;
  uint8_t*at=s->text_scratch+q->rva-4096;
  if(memcmp(at,q->original,q->length)&&memcmp(at,q->installed,q->length))return 0;
  memcpy(at,q->original,q->length);
 }
 uint8_t digest[32];ap_sha256(s->text_scratch,text_size[index],digest);int good=ap_constant_equal(digest,text_sha[index],32);ap_secure_zero(digest,32);return good;
}
int mp_identity(MP_STATE*s,int bridge){
 if(!mp_live(s))return 0;MP_BINDING*b=&s->binding;HANDLE driver=0;CONFIG*config=0;
 if(!method((void*)b->database->get_driver)||!method((void*)b->st->bs->handle_protocol))return 0;
 ES status=b->database->get_driver(b->database,b->hii,&driver);if(!mp_live(s)||FAILED(status)||driver!=b->driver)return 0;
 status=b->st->bs->handle_protocol(driver,&config_guid,(void**)&config);if(!mp_live(s)||FAILED(status)||config!=b->config)return 0;
 if(b->config->extract!=(uint8_t*)b->setup_base+0x2240||b->config->route!=(ROUTE)((uint8_t*)b->setup_base+0x2248)||
  b->config->callback!=(bridge?mp_callback:(CALLBACK)((uint8_t*)b->setup_base+0x2250)))return 0;
 if(s->identity_busy)return 0;s->identity_busy=1;
 int valid=module(s,b->driver,b->setup_base,b->setup_size,0)&&module(s,b->tse_driver,b->tse_base,b->tse_size,1)&&mp_live(s);
 s->identity_busy=0;return valid;
}
MP_RESULT mp_bind(MP_STATE*s,const MP_BINDING*b,const MP_AUTHORITY*a){
 if(mp_current||!w890_memory_present(s,sizeof(*s),1)||!w890_memory_present(b,sizeof(*b),0)||!w890_memory_present(a,sizeof(*a),0)||
  a->revision!=MP_REVISION||a->size!=sizeof(*a)||!a->window_valid||!a->publication_finished||!a->restoration_finished||!a->management_enter||!a->management_valid||!a->management_leave)return MP_INVALID;
 memset(s,0,sizeof(*s));s->revision=MP_REVISION;s->binding=*b;s->authority=*a;mp_current=s;
 if(!w890_memory_present(b->st,sizeof(ST),0)||!w890_memory_present(b->st->bs,sizeof(BS),0)||!w890_memory_present(b->database,sizeof(HII),0)||!w890_memory_present(b->strings,sizeof(STRINGS),0))goto invalid;
 s->pinned_bs=b->st->bs;
 {void*methods[10]={(void*)b->st->bs->handle_protocol,(void*)b->st->bs->allocate_pool,(void*)b->st->bs->free_pool,
  (void*)b->database->get_driver,(void*)b->database->export_list,(void*)b->database->update_list,(void*)b->strings->new_string,
  b->strings->get_string,(void*)b->strings->set_string,(void*)b->strings->languages};memcpy(s->service_methods,methods,sizeof(methods));}
 if(b->patch_count>MP_MAX_PATCHES||(b->patch_count&&!w890_memory_present(b->patches,sizeof(MP_PATCH)*b->patch_count,0)))goto invalid;
 for(unsigned i=0;i<b->patch_count;i++){
  const MP_PATCH*p=&b->patches[i];uint32_t size=p->module?174073:597466;
  if(p->module>1||p->reserved||!p->length||p->length>32||p->rva<4096||p->rva-4096>size||p->length>size-(p->rva-4096))goto invalid;
  for(unsigned j=0;j<i;j++){const MP_PATCH*q=&b->patches[j];if(p->module==q->module&&p->rva<q->rva+q->length&&q->rva<p->rva+p->length)goto invalid;}
  const uint8_t*base=p->module?b->setup_base:b->tse_base;
  if(!w890_memory_present(base+p->rva,p->length,0)||memcmp(base+p->rva,p->original,p->length))goto invalid;
  s->patches[i]=*p;
 }s->patch_count=b->patch_count;
 s->original_extract=(uint8_t*)b->setup_base+0x2240;s->original_route=(ROUTE)((uint8_t*)b->setup_base+0x2248);s->original_callback=(CALLBACK)((uint8_t*)b->setup_base+0x2250);
 if(!mp_identity(s,0))goto invalid;
 s->stage=MP_BOUND;return MP_OK;
invalid:s->stage=MP_TERMINAL;s->ended=1;return MP_INVALID;
}
void mp_end_boot(MP_STATE*s){if(s==mp_current){s->ended=1;s->stage=MP_TERMINAL;s->active_window=0;s->management_ticket=0;}}
uint8_t*mp_alloc(MP_STATE*s,uint64_t ticket,UN n){
 void*p=0;if(!mp_window(s,ticket)||!n||n>MP_MAX_PACKAGE||!method((void*)s->binding.st->bs->allocate_pool))return 0;
 ES status=s->binding.st->bs->allocate_pool(4,n,&p);if(FAILED(status)||!mp_window(s,ticket)||!w890_memory_present(p,n,1))return 0;return p;
}
void mp_free(MP_STATE*s,void*p){if(p&&mp_window(s,s->active_window)&&method((void*)s->binding.st->bs->free_pool))s->binding.st->bs->free_pool(p);}
uint8_t*mp_export(MP_STATE*s,uint64_t ticket,UN*n){
 *n=0;if(!mp_window(s,ticket)||!method((void*)s->binding.database->export_list))return 0;
 ES status=s->binding.database->export_list(s->binding.database,s->binding.hii,n,0);
 if(!mp_window(s,ticket)||status!=ERR(5)||*n<24||*n>MP_MAX_PACKAGE)return 0;
 UN capacity=*n;uint8_t*p=mp_alloc(s,ticket,capacity);if(!p)return 0;
 status=s->binding.database->export_list(s->binding.database,s->binding.hii,n,p);
 if(!mp_window(s,ticket)||FAILED(status)||*n>capacity||*n<24||mp_u32(p+16)!=*n){mp_free(s,p);return 0;}return p;
}
