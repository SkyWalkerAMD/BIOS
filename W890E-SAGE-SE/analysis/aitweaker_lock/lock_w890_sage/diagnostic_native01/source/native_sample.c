#include "native_sample.h"
static void zero(void *p,size_t n){uint8_t *b=p;while(n--)*b++=0;}
static int equal(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static uint64_t get(const void *p,size_t n){const uint8_t *b=p;uint64_t v=0;for(size_t i=0;i<n;i++)v|=(uint64_t)b[i]<<(8*i);return v;}
static int pointer(uint64_t p,size_t alignment){return p>=4096&&p<0x0000800000000000ULL&&!(p&(alignment-1));}
int ns_range(const void *map,size_t bytes,size_t stride,uint32_t version,uint64_t address,size_t length){
 if(!map||version!=1||stride<40||stride>256||!bytes||bytes>65536||bytes%stride||bytes/stride>2048||
    !length||!pointer(address,1)||length>0x0000800000000000ULL-address)return 0;
 uint64_t end=address+length;unsigned cover=0;
 for(size_t off=0;off<bytes;off+=stride){
  const uint8_t *d=(const uint8_t *)map+off;
  uint64_t p=get(d+8,8),pages=get(d+24,8),attr=get(d+32,8);uint32_t type=(uint32_t)get(d,4);
  if((p&4095)||!pages||pages>UINT64_MAX/4096||p>UINT64_MAX-pages*4096)return 0;
  uint64_t limit=p+pages*4096;
  if(address<limit&&p<end){
   if(address<p||end>limit||type<1||type>6||(attr&0x2000)||++cover>1)return 0;
  }
 }
 return cover==1;
}
static int globals(NS_COPY copy,void *context,uint64_t base,NS_GLOBALS *g){
 zero(g,sizeof(*g));
 return copy(context,base+0xafdd0,&g->app,8)&&copy(context,base+0xafcb0,&g->stage,8)&&
 copy(context,base+0xafbc8,&g->boot_services,8)&&copy(context,base+0xbabe8,&g->string_hii,8)&&
 copy(context,base+0xafddc,&g->history_root,4)&&copy(context,base+0xafde0,&g->history_capacity,4)&&
 copy(context,base+0xafde8,&g->history,8)&&copy(context,base+0xafe00,&g->history_count,4);
}
int ns_sample(NS_COPY copy,void *context,uint64_t base,size_t image_bytes,NS_SAMPLE *out){
 NS_SAMPLE sample;NS_GLOBALS again;uint8_t app[0x60],app_again[0x60],page[0x68],page_again[0x68];uint64_t page_again_ptr=0;
 if(!out)return NS_BAD_IMAGE;zero(out,sizeof(*out));zero(&sample,sizeof(sample));
 if(!copy||!pointer(base,4096)||image_bytes!=909312||base>0x0000800000000000ULL-image_bytes)return NS_BAD_IMAGE;
 if(!globals(copy,context,base,&sample.globals))return NS_GLOBAL_READ;
 if(!sample.globals.app){if(!globals(copy,context,base,&again)||!equal(&sample.globals,&again,sizeof(again)))return NS_CHANGED;*out=sample;return NS_INACTIVE;}
 if(!pointer(sample.globals.app,8)||!copy(context,sample.globals.app,app,sizeof(app)))return NS_APP_READ;
 sample.current_index=(uint32_t)get(app+0x28,4);sample.page_count=(uint32_t)get(app+0x2c,4);sample.page_array=get(app+0x30,8);
 sample.redraw=app[0x58];sample.exit_flag=app[0x5a];sample.menu_mode=(uint32_t)get(app+0x5c,4);
 if(!sample.page_count||sample.page_count>4096||sample.current_index>=sample.page_count||!pointer(sample.page_array,8)||
    sample.page_array>UINT64_MAX-(uint64_t)sample.page_count*8||sample.globals.history_capacity>4096||
    sample.globals.history_count>sample.globals.history_capacity)return NS_APP_BOUNDS;
 uint64_t slot=sample.page_array+(uint64_t)sample.current_index*8;
 if(!copy(context,slot,&sample.page,8)||!pointer(sample.page,8)||!copy(context,sample.page,page,sizeof(page)))return NS_PAGE_READ;
 sample.hii=get(page+0x20,8);sample.form=(uint16_t)get(page+0x2a,2);sample.index=(uint16_t)get(page+0x30,2);sample.parent=(uint16_t)get(page+0x32,2);
 sample.page_flags=page[0x34];sample.frame_count=(uint32_t)get(page+0x4c,4);sample.frames=get(page+0x50,8);
 sample.extra_count=(uint32_t)get(page+0x58,4);sample.extras=get(page+0x60,8);
 if(sample.index!=sample.current_index||sample.frame_count>64||sample.extra_count>4096||
    (sample.frame_count&&!pointer(sample.frames,8))||(sample.extra_count&&!pointer(sample.extras,8)))return NS_PAGE_BOUNDS;
 if(!globals(copy,context,base,&again)||!equal(&sample.globals,&again,sizeof(again))||
    !copy(context,sample.globals.app,app_again,sizeof(app_again))||!equal(app,app_again,sizeof(app))||
    !copy(context,slot,&page_again_ptr,8)||page_again_ptr!=sample.page||
    !copy(context,sample.page,page_again,sizeof(page_again))||!equal(page,page_again,sizeof(page)))return NS_CHANGED;
 *out=sample;return NS_OK;
}
