/* Diagnostic snapshots only. No variable API, firmware callback or native write. */
#include "core.h"
#include "password_core.h"
#include "known_profiles.h"
static uint16_t u16(const uint8_t *p){return p[0]|((uint16_t)p[1]<<8);}
static uint32_t u32(const uint8_t *p){return u16(p)|((uint32_t)u16(p+2)<<16);}
static uint64_t u64(const uint8_t *p){return u32(p)|((uint64_t)u32(p+4)<<32);}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(n>>(i*8));}
static int same(const void *a,const void *b,size_t n){const uint8_t *p=a,*q=b;while(n--)if(*p++!=*q++)return 0;return 1;}
static void zero(void *p,size_t n){uint8_t *b=p;while(n--)*b++=0;}
static int read_at(const H6_HOST *h,uint64_t base,uint64_t size,uint32_t off,void *out,size_t n){
 return n&&off<=size&&n<=size-off&&base<=UINT64_MAX-off&&base+off<=UINT64_MAX-n&&h->copy(h->context,base+off,out,n);
}
const H6_PROFILE *h6_profile(const uint8_t *g){if(!g)return 0;for(size_t i=0;i<sizeof(h6_profiles)/sizeof(h6_profiles[0]);i++)if(same(g,h6_profiles[i].guid,16))return h6_profiles+i;return 0;}
size_t h6_profile_count(void){return sizeof(h6_profiles)/sizeof(h6_profiles[0]);}
const H6_PROFILE *h6_profile_at(size_t n){return n<h6_profile_count()?h6_profiles+n:0;}
const char *h6_status(unsigned n){static const char *s[]={"MATCH","HEADER","RANGE","ALLOC","LAYOUT","RELOC_RANGE","RELOC_TABLE","RELOC_VALUE","MISMATCH","UNKNOWN","FREE","CHANGED"};return n<sizeof(s)/sizeof(*s)?s[n]:"INVALID";}
int h6_probe(const H6_HOST *h,uint64_t base,uint64_t size,const H6_PROFILE *p,H6_RESULT *r){
 uint8_t dos[64],nt[24],opt[240],sec[40];uint8_t *text=0,*reloc=0;uint32_t pe,sections,options,table;unsigned found=0;
 if(!r)return 0;zero(r,sizeof(*r));r->status=H6_HEADER;
 if(!h||!h->copy||!h->alloc||!h->free||base<4096||size<64||size>64U*1024U*1024U||base>UINT64_MAX-size)return 0;
 if(!read_at(h,base,size,0,dos,sizeof(dos)))goto range;
 if(u16(dos)!=0x5a4d||(pe=u32(dos+60))<64||pe>0x1000)goto done;
 if(!read_at(h,base,size,pe,nt,sizeof(nt)))goto range;
 if(u32(nt)!=0x4550||u16(nt+4)!=0x8664)goto done;
 sections=u16(nt+6);options=u16(nt+20);
 if(!sections||sections>96||options!=240)goto done;
 if(!read_at(h,base,size,pe+24,opt,sizeof(opt)))goto range;
 if(u16(opt)!=0x20b||u16(opt+68)<10||u16(opt+68)>12||u32(opt+108)<6)goto done;
 r->entry=u32(opt+16);r->image_size=u32(opt+56);r->reloc_rva=u32(opt+152);r->reloc_size=u32(opt+156);
 if(!r->image_size||r->image_size>size||r->entry>=r->image_size)goto done;
 table=pe+24+options;
 if(table>0x10000||sections*40>0x10000-table||table+sections*40>u32(opt+60))goto done;
 for(unsigned i=0;i<sections;i++){
  if(!read_at(h,base,size,table+i*40,sec,sizeof(sec)))goto range;
  uint32_t v=u32(sec+12),n=u32(sec+8);if(v>r->image_size||n>r->image_size-v)goto done;
  if(same(sec,".text\0\0\0",8)){
   if(++found!=1||!n||n>H6_MAX_TEXT||(u32(sec+36)&0x20000000U)==0)goto done;
   r->text_rva=v;r->text_size=n;
  }
 }
 if(found!=1)goto done;
 text=h->alloc(h->context,r->text_size);if(!text){r->status=H6_ALLOC_FAILED;goto done;}
 if(!read_at(h,base,size,r->text_rva,text,r->text_size))goto range;
 ap_sha256(text,r->text_size,r->raw);r->raw_valid=1;
 if(!p){r->status=H6_UNKNOWN;goto done;}
 if(r->image_size!=p->image_size||r->entry!=p->entry||r->text_rva!=p->text_rva||r->text_size!=p->text_size||
    r->reloc_rva!=p->reloc_rva||r->reloc_size!=p->reloc_size||
    (u64(opt+24)!=p->preferred&&u64(opt+24)!=base)||p->count>8){r->status=H6_LAYOUT;goto done;}
 if(p->reloc_size){
  if(p->reloc_size>H6_MAX_RELOC||p->reloc_rva>size||p->reloc_size>size-p->reloc_rva){r->status=H6_RELOC_RANGE;goto done;}
  reloc=h->alloc(h->context,p->reloc_size);if(!reloc){r->status=H6_ALLOC_FAILED;goto done;}
  if(!read_at(h,base,size,p->reloc_rva,reloc,p->reloc_size)){r->status=H6_RELOC_RANGE;goto done;}
  uint8_t digest[32];ap_sha256(reloc,p->reloc_size,digest);
  if(!same(digest,p->reloc_sha,32)){r->status=H6_RELOC_TABLE;goto done;}
 }
 for(unsigned i=0;i<p->count;i++){
  const H6_RELOC *f=p->fixups+i;
  if(f->type!=10||f->rva<r->text_rva||r->text_size<8||f->rva-r->text_rva>r->text_size-8||
     (i&&f->rva<p->fixups[i-1].rva+8)){r->status=H6_RELOC_RANGE;goto done;}
  uint8_t *q=text+f->rva-r->text_rva;
  if(u64(q)!=f->original+(base-p->preferred)){r->status=H6_RELOC_VALUE;goto done;}
  put64(q,f->original);
 }
 ap_sha256(text,r->text_size,r->normalized);r->normalized_valid=1;
 r->status=same(r->normalized,p->text_sha,32)?H6_OK:H6_TEXT_MISMATCH;
 goto done;
range:r->status=H6_RANGE;
done:
 if(reloc&&!h->free(h->context,reloc))r->status=H6_FREE_FAILED;
 if(text&&!h->free(h->context,text))r->status=H6_FREE_FAILED;
 return r->status==H6_OK;
}
