#include "tse_audit.h"
static GUID browser_guid={0xb9d4c360,0xbcfb,0x4f9b,{0x92,0x98,0x53,0xc1,0x36,0x98,0x22,0x58}};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
typedef ES (EA *GET_MAP)(UN *,void *,UN *,UN *,uint32_t *);
typedef struct {uint8_t *map;UN n,stride;uintptr_t image;} AUDIT;
static uint32_t probe_crc32(const uint8_t *b,UN n){
 uint32_t c=0xffffffffU;for(UN i=0;i<n;i++){c^=b[i];for(unsigned k=0;k<8;k++)c=(c>>1)^(0xedb88320U&(0U-(c&1U)));}return ~c;
}
static void num(const char *name,uint64_t v){logtext(name);loghex(v,16);logtext("\r\n");}
static int readable(AUDIT *a,uintptr_t p,UN n){return tse_readable(a->map,a->n,a->stride,p,n);}
static int rd(AUDIT *a,uintptr_t p,UN n,void *out){if(!readable(a,p,n))return 0;memcpy(out,(const void *)p,n);return 1;}
static int word(AUDIT *a,uintptr_t p,uint64_t *v){return rd(a,p,8,v);}
static uint64_t global(AUDIT *a,unsigned rva){uint64_t v=0;(void)word(a,a->image+rva,&v);return v;}
static int forms(AUDIT *a,uintptr_t p,uint32_t *size,uint32_t *crc){
 uint8_t h[4];if(!rd(a,p,4,h))return 0;*size=u32(h)&0xffffff;
 if(h[3]!=2||*size<43||*size>1048576||!readable(a,p,*size))return 0;
 *crc=probe_crc32((const uint8_t *)p,*size);return 1;
}
static void cache(AUDIT *a,HANDLE target,const uint8_t *expected,UN expected_n){
 uintptr_t entries=(uintptr_t)global(a,0x18f1a0);uint64_t count=global(a,0x18f190);
 num("CACHE_COUNT=",count);num("EXPECTED_FORM_CRC=",expected?probe_crc32(expected,expected_n):0);
 if(!count||count>512||!readable(a,entries,count*0x30)){logtext("CACHE_UNAVAILABLE\r\n");return;}
 unsigned matches=0;
 for(unsigned i=0;i<count;i++){
  uint8_t e[0x30];if(!rd(a,entries+i*0x30,sizeof(e),e))return;
  if(u64(e+8)!=(uintptr_t)target)continue;matches++;
  uintptr_t p=(uintptr_t)u64(e);uint32_t n=0,crc=0;
  num("CACHE_TARGET_INDEX=",i);num("CACHE_FORM_PTR=",p);
  if(forms(a,p,&n,&crc)){num("CACHE_FORM_BYTES=",n);num("CACHE_FORM_CRC=",crc);
   num("CACHE_MATCHES_EXPECTED=",expected&&n==expected_n&&eq((const void *)p,expected,n));}
  else logtext("CACHE_FORM_INVALID\r\n");
 }
 num("CACHE_TARGET_MATCHES=",matches);
}
static void pages(AUDIT *a,HANDLE target){
 uintptr_t base=(uintptr_t)global(a,0x1938e0),table=(uintptr_t)global(a,0x1937e8),controls=(uintptr_t)global(a,0x1937f8);
 uint32_t count=0;num("PAGE_BASE=",base);num("PAGE_TABLE=",table);num("CONTROL_BASE=",controls);
 if(!readable(a,base,4)||!readable(a,controls,4)){logtext("PAGE_BASE_UNAVAILABLE\r\n");return;}
 if(!rd(a,table,4,&count)||!count||count>4096||!readable(a,table,4+(UN)count*4)){logtext("PAGE_TABLE_UNAVAILABLE\r\n");return;}
 num("PAGE_COUNT=",count);unsigned target_count=0,new_count=0,advanced=0;
 for(unsigned i=0;i<count;i++){
  uint32_t offset=0;uint8_t page[32];if(!rd(a,table+4+i*4,4,&offset)||offset>16*1024*1024||!rd(a,base+offset,sizeof(page),page))continue;
  if(u64(page)!=(uintptr_t)target)continue;target_count++;
  uint16_t form=u16(page+10);if(form>=0x3100&&form<=0x3104)new_count++;
  if(form!=10005)continue;advanced++;
  uint32_t n=u32(page+28);num("ADV_PAGE_INDEX=",i);num("ADV_CONTROL_COUNT=",n);
  if(n>256||!readable(a,base+offset+32,(UN)n*4))continue;
  /* Last controls identify whether the extra goto was actually parsed. */
  for(unsigned j=n>4?n-4:0;j<n;j++){
   uint32_t coff=0;uint8_t ctrl[64];if(!rd(a,base+offset+32+j*4,4,&coff)||coff>16*1024*1024||!rd(a,controls+coff,64,ctrl))continue;
   logtext("ADV_CTRL ");loghex(j,4);logtext(" Q=");loghex(u16(ctrl+12),4);logtext(" TYPE=");loghex(u16(ctrl+20),4);
   logtext(" PAGE=");loghex(u16(ctrl+22),4);logtext(" TARGET=");loghex(u16(ctrl+24),4);logtext(" IFR=");loghex(u64(ctrl+40),16);
   uint8_t op[4];if(rd(a,(uintptr_t)u64(ctrl+40),4,op)){logtext(" OP=");loghex(u32(op),8);}logtext("\r\n");
  }
 }
 num("TARGET_PAGE_COUNT=",target_count);num("NEW_IPMI_PAGE_COUNT=",new_count);num("ADV_MATCHES=",advanced);
}
static void queue(AUDIT *a,HANDLE target){
 uint8_t flag=0;(void)rd(a,a->image+0x18f1d8,1,&flag);num("NOTIFY_PENDING=",flag);
 uintptr_t q=(uintptr_t)global(a,0x18f1f8);if(!q){num("NOTIFY_COUNT=",0);return;}
 uint8_t h[24];if(!rd(a,q,sizeof(h),h)){logtext("NOTIFY_HEADER_INVALID\r\n");return;}
 uint64_t count=u64(h);num("NOTIFY_COUNT=",count);if(count>512){logtext("NOTIFY_LIMIT\r\n");return;}
 uintptr_t next=(uintptr_t)u64(h+8);unsigned seen=0,target_count=0;
 while(next&&seen<count&&seen<512){
  uint8_t node[48];if(!rd(a,next,sizeof(node),node)){logtext("NOTIFY_NODE_INVALID\r\n");break;}
  if(u64(node)==(uintptr_t)target){
   target_count++;num("NOTIFY_TARGET_TYPE=",u64(node+8));uint32_t n=0,c=0;
   if(forms(a,(uintptr_t)u64(node+16),&n,&c)){num("NOTIFY_FORM_BYTES=",n);num("NOTIFY_FORM_CRC=",c);}
  }
  seen++;next=(uintptr_t)u64(node+40);
 }
 num("NOTIFY_TARGET_COUNT=",target_count);num("NOTIFY_WALK_COMPLETE=",seen==count&&!next);
}
ES tse_snapshot(const char *tag,HANDLE target,const uint8_t *expected,UN expected_n){
 logtext("TSE_BEGIN ");logtext(tag);logtext("\r\n");ES e;void *browser=0;HANDLE *images=0;UN count=0;
 e=gST->bs->locate_protocol(&browser_guid,0,&browser);if(FAILED(e)||!browser)return ERR(14);
 uintptr_t send=0;/* FormBrowser2.SendForm is the first method. */
 memcpy(&send,browser,8);
 e=gST->bs->locate_handles(2,&loaded_guid,0,&count,&images);if(FAILED(e)||!images)return ERR(14);
 AUDIT a={0};unsigned matches=0;
 if(count<=4096)for(UN i=0;i<count;i++){
  LOADED *li=0;if(FAILED(gST->bs->handle_protocol(images[i],&loaded_guid,(void **)&li))||!li)continue;
  uintptr_t start=(uintptr_t)li->image_base;
  if(li->image_size==0x1e6180&&send>=start&&send-start==0x2aa7c){a.image=start;matches++;}
 }
 gST->bs->free_pool(images);if(matches!=1){num("TSE_OWNER_MATCHES=",matches);return ERR(3);}
 if(FAILED(e=gST->bs->allocate_pool(4,1048576,(void **)&a.map)))return e;
 a.n=1048576;UN key=0;uint32_t version=0;
 e=((GET_MAP)gST->bs->get_memory_map)(&a.n,a.map,&key,&a.stride,&version);
 if(FAILED(e)||version!=1||a.n>1048576||!readable(&a,a.image,0x1e6180)){e=ERR(3);goto done;}
 static const unsigned code[][2]={{0x2aa7c,0x0021324d},{0x31ac4,0xeec5f6d6},{0x349e0,0x0fe37311}};
 for(unsigned i=0;i<3;i++)if(probe_crc32((const uint8_t *)(a.image+code[i][0]),64)!=code[i][1]){e=ERR(33);goto done;}
 num("TSE_EXACT_IMAGE=",1);num("TSE_STATE=",global(&a,0x1801b8));
 cache(&a,target,expected,expected_n);pages(&a,target);queue(&a,target);e=0;
done:
 gST->bs->free_pool(a.map);num("TSE_END_STATUS=",e);return e;
}
