#include "layout.h"
#include "../password/core/password_core.h"
static int equal(const void *a,const void *b,size_t n){const uint8_t*x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static uint32_t read32(const void*p){const uint8_t*b=p;return(uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;}
static uint64_t read64(const void*p){const uint8_t*b=p;uint64_t r=0;for(unsigned i=0;i<8;i++)r|=(uint64_t)b[i]<<(8*i);return r;}
static int span(uint32_t p,uint32_t n,uint32_t size){return p<size&&n&&n<=size-p;}
static int hash(const void*p,size_t n,const uint8_t expected[32]){uint8_t h[32];ap_sha256(p,n,h);return equal(h,expected,32);}
static int shape(const I05_LAYOUT*l){return equal(l->magic,"W890L05",8)&&l->revision==I05_LAYOUT_REVISION&&l->size==sizeof(*l)&&
 l->image_size>=0xde000&&l->image_size<=0x2100000&&l->original_entry_rva==0x6480&&l->extension_rva==0xde000&&
 l->section_count>=7&&l->section_count<=I05_MAX_SECTIONS&&l->patch_count<=I05_MAX_PATCHES&&
 l->span_count&&l->span_count<=I05_MAX_SPANS&&l->fixup_count<=I05_MAX_FIXUPS&&
 l->export_count<=I05_MAX_SYMBOLS&&l->trampoline_count<=I05_MAX_SYMBOLS-l->export_count&&l->header_bytes==1024&&l->reserved==0&&
 span(l->slot_rva,sizeof(*l),l->image_size)&&span(l->entry_rva,1,l->image_size);}
const I05_LAYOUT*i05_layout_get(void){return shape(&i05_static_layout)?&i05_static_layout:0;}
uint32_t i05_layout_symbol(const char*name,uint32_t kind){
 const I05_LAYOUT*l=i05_layout_get();if(!l||!name||kind>1)return 0;
 for(uint32_t i=0;i<l->export_count+l->trampoline_count;i++){const I05_SYMBOL*s=&l->symbols[i];if(s->kind!=kind)continue;
  for(unsigned j=0;j<40;j++){if(name[j]!=s->name[j])break;if(!name[j])return span(s->rva,1,l->image_size)?s->rva:0;}}
 return 0;
}
int i05_layout_live(uintptr_t base,uint64_t size){
 const I05_LAYOUT*l=i05_layout_get();if(!l||size!=l->image_size||base<4096||size>UINTPTR_MAX-base||
   (uintptr_t)l!=base+l->slot_rva)return 0;
 const uint8_t*b=(const uint8_t*)base;uint8_t header[1024];for(unsigned i=0;i<sizeof(header);i++)header[i]=b[i];
 uint32_t nt=read32(header+0x3c);if(nt!=192||!equal(header+nt,"PE\0\0",4)||read32(header+nt+24+56)!=size)return 0;
 /* EDK II's genuine PE loader writes the actual base into ImageBase during
  * relocation. Only zero/preferred or this exact proved image base is valid. */
 uint64_t header_base=read64(header+nt+24+24);if(header_base&&header_base!=base)return 0;
 for(unsigned i=0;i<8;i++)header[nt+24+24+i]=0;
 for(unsigned i=0;i<4;i++)header[nt+24+64+i]=0;
 if(!hash(header,sizeof(header),l->header_sha256))return 0;
 for(uint32_t i=0;i<l->patch_count;i++){const I05_PATCH*p=&l->patches[i];
  if(p->module||p->length<5||p->length>32||!span(p->rva,p->length,l->image_size)||!span(p->target_rva,1,l->image_size)||
    p->mode>1||(p->mode==1&&p->length!=5)||p->installed[0]!=(p->mode==1?0xe8:0xe9)||
    (uint64_t)((int64_t)p->rva+5+(int32_t)read32(p->installed+1))!=p->target_rva||
    !equal(b+p->rva,p->installed,p->length))return 0;
 }
 for(uint32_t i=0;i<l->span_count;i++){const I05_SPAN*s=&l->spans[i];if(!span(s->rva,s->length,l->image_size)||
   !hash(b+s->rva,s->length,s->sha256))return 0;}
 for(uint32_t i=0;i<l->fixup_count;i++){const I05_FIXUP*f=&l->fixups[i];if(f->reserved||!span(f->rva,8,l->image_size)||
   f->preferred_value>=size||read64(b+f->rva)!=base+f->preferred_value)return 0;}
 return 1;
}
