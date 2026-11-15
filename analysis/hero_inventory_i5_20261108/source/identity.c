/* Per-boot current-host capture, never a frozen inventory body.
 * The separate test peer policy binds this initial ISO to .71 only.
 */
#include "i5.h"
#include "smbios_bounded.h"
#include "target_identity.h"
typedef struct {uint32_t type,pad;uint64_t physical,virtual_address,pages,attributes;} MD;
static GUID sm3={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
static GUID sm2={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0,0x90,0x27,0x3f,0xc1,0x4d}};
static uint8_t memory_map[131072],source[TABLE_CAP],entry_copy[64];
static UN map_bytes,map_stride;static SM_ENTRY chosen;static SM_TABLE meta;
static HIC_CATALOG catalog;static HIC_SCRATCH scratch;
static const uint8_t *live_table;static int valid;
static int map_read(void){
 ES (EA *get_map)(UN *,void *,UN *,UN *,uint32_t *)=(void *)gST->bs->get_memory_map;
 UN key;uint32_t version;map_bytes=sizeof(memory_map);map_stride=0;
 if(!get_map||FAILED(get_map(&map_bytes,memory_map,&key,&map_stride,&version)))return 0;
 return version==1&&map_bytes<=sizeof(memory_map)&&map_stride>=sizeof(MD)&&map_stride<=256&&map_bytes%map_stride==0;
}
static int readable(const void *pointer,UN bytes){
 UN at=(UN)pointer;if(!at||!bytes||bytes>~at)return 0;UN end=at+bytes;
 while(at<end){UN covered=at;
  for(UN off=0;off<map_bytes;off+=map_stride){MD *d=(MD *)(void *)(memory_map+off);
   if(!((d->type>=1&&d->type<=7)||d->type==9||d->type==10)||d->pages>(~(UN)0)/4096)continue;
   UN len=d->pages*4096;if(len>~d->physical)continue;UN last=d->physical+len;
   if(d->physical<=at&&at<last&&last>covered)covered=last;
  }
  if(covered==at)return 0;at=covered<end?covered:end;
 }return 1;
}
static int capture_entry(const uint8_t *p,unsigned kind){
 if(!readable(p,8))return 0;unsigned n=p[kind==3?6:5];
 if(n<24||n>64||!readable(p,n))return 0;memcpy(entry_copy,p,n);
 if(smbios_entry(entry_copy,n,kind,&chosen))return 0;
 live_table=(const uint8_t *)(UN)chosen.address;
 if(!readable(live_table,chosen.bound)||smbios_table(live_table,chosen.bound,chosen.count,&meta))return 0;
 memcpy(source,live_table,meta.used);SM_TABLE check;
 return !smbios_table(source,meta.used,chosen.count,&check)&&check.used==meta.used&&check.crc==meta.crc&&eq(source,live_table,meta.used);
}
ES i5_capture_source(void){
 valid=0;if(!gST||!gST->bs||!gST->tables||!gST->table_count||gST->table_count>1024||!map_read())return ERR(33);
 if(!readable(gST->tables,gST->table_count*sizeof(CT)))return ERR(33);
 const uint8_t *p3=0,*p2=0;unsigned n3=0,n2=0;
 for(UN i=0;i<gST->table_count;i++){
  if(eq(&gST->tables[i].guid,&sm3,16)){p3=gST->tables[i].table;n3++;}
  if(eq(&gST->tables[i].guid,&sm2,16)){p2=gST->tables[i].table;n2++;}
 }
 if(n3>1||n2>1||!((n3==1&&capture_entry(p3,3))||(n2==1&&capture_entry(p2,2))))return ERR(33);
 int e=HeroInventoryBuild(source,meta.used,(uint8_t)chosen.major,(uint8_t)chosen.minor,&catalog,&scratch);
 status("I5_DYNAMIC_CATALOG_RESULT",(ES)e);if(e)return ERR(33);
 if(!same(catalog.board_model,"ROG MAXIMUS Z790 HERO")||!same(catalog.bios_version,"3107"))return ERR(15);
 /* Test-only endpoint identity is isolated from catalogue generation. */
 const uint8_t *p=source,*end=p+meta.used;unsigned matches=0;
 while(p<end){unsigned len=p[1];const uint8_t *q=p+len;while(q+1<end&&(q[0]||q[1]))q++;
  if(p[0]==1&&len>=24&&eq(p+8,target_uuid,16))matches++;
  p=q+2;
 }
 if(matches!=1)return ERR(15);
 strcopy(report.board,sizeof(report.board),catalog.board_model);strcopy(report.bios,sizeof(report.bios),catalog.bios_version);
 status("I5_SOURCE_BYTES",meta.used);status("I5_SOURCE_CRC32",meta.crc);status("I5_CATALOG_ITEMS",catalog.item_count);
 status("I5_CPU_COUNT",catalog.cpu_count);status("I5_DIMM_SLOTS",catalog.dimm_count);
 logtext("I5_SOURCE_UUID=");logtext(catalog.uuid);logtext("\r\nI5_SOURCE_IS_CURRENT_HOST_NOT_FROZEN_PAYLOAD\r\n");
 valid=1;return 0;
}
int i5_source_valid(void){
 if(!valid||!map_read()||!readable(live_table,meta.used))return 0;
 return eq(source,live_table,meta.used);
}
const HIC_CATALOG *i5_catalog(void){return valid?&catalog:0;}
int i3_target_valid(void){return i5_source_valid();}
int i3_inventory_source_valid(void){return i5_source_valid();}
uint64_t i3_inventory_source_epoch(void){return (uint64_t)(UN)source;}
int i3_publication_runtime_ready(void){return 0;}
void i3_identity_log(void){status("I5_CURRENT_SOURCE_VALID",i5_source_valid());}
