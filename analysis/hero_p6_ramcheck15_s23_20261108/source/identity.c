/* Read-only, bounded identity gate. Unused OEM strings are not interpreted. */
#include "smbios_bounded.h"
#include "target_identity.h"
typedef struct {uint32_t type,pad;uint64_t physical,virtual_address,pages,attributes;} MD;
static GUID sm3={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
static GUID sm2={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0,0x90,0x27,0x3f,0xc1,0x4d}};
static uint8_t memory_map[131072],source[TABLE_CAP],entry[64];
static UN map_bytes,map_stride;static SM_ENTRY chosen;static SM_TABLE meta;
int memory_refresh(void){
 ES(EA *get_map)(UN *,void *,UN *,UN *,uint32_t *)=(void *)gST->bs->get_memory_map;
 UN key;uint32_t version;map_bytes=sizeof(memory_map);map_stride=0;
 if(!get_map||FAILED(get_map(&map_bytes,memory_map,&key,&map_stride,&version)))return 0;
 return version==1&&map_bytes<=sizeof(memory_map)&&map_stride>=sizeof(MD)&&map_stride<=256&&map_bytes%map_stride==0;
}
int memory_readable(const void *pointer,UN bytes){
 UN at=(UN)pointer;if(!at||!bytes||bytes>~at)return 0;UN end=at+bytes;
 while(at<end){UN covered=at;for(UN off=0;off<map_bytes;off+=map_stride){MD *d=(MD *)(void *)(memory_map+off);
  if(!((d->type>=1&&d->type<=7)||d->type==9||d->type==10)||d->pages>(~(UN)0)/4096)continue;
  UN len=d->pages*4096;if(len>~d->physical)continue;UN last=d->physical+len;
  if(d->physical<=at&&at<last&&last>covered)covered=last;
 }if(covered==at)return 0;at=covered<end?covered:end;}return 1;
}
static int capture(const uint8_t *p,unsigned kind){
 if(!memory_readable(p,8))return 0;unsigned n=p[kind==3?6:5];
 if(n<24||n>64||!memory_readable(p,n))return 0;memcpy(entry,p,n);
 if(smbios_entry(entry,n,kind,&chosen))return 0;
 const uint8_t *table=(const uint8_t *)(UN)chosen.address;
 if(!memory_readable(table,chosen.bound)||smbios_table(table,chosen.bound,chosen.count,&meta))return 0;
 memcpy(source,table,meta.used);SM_TABLE check;
 return !smbios_table(source,meta.used,chosen.count,&check)&&check.used==meta.used&&check.crc==meta.crc&&eq(source,table,meta.used);
}
static int string_is(const uint8_t *p,const uint8_t *end,unsigned index,const char *expected){
 if(!index)return 0;for(unsigned i=1;p<end&&*p;i++){const uint8_t *q=p;while(q<end&&*q)q++;if(q==end)return 0;
  if(i==index){size_t n=0;while(expected[n])n++;return n==(size_t)(q-p)&&eq(p,expected,n);}p=q+1;}return 0;
}
ES identity_check(void){
 if(!gST||!gST->tables||!gST->table_count||gST->table_count>1024||!memory_refresh()||!memory_readable(gST->tables,gST->table_count*sizeof(CT)))return ERR(33);
 const uint8_t *p3=0,*p2=0;unsigned n3=0,n2=0;
 for(UN i=0;i<gST->table_count;i++){
  if(eq(&gST->tables[i].guid,&sm3,16)){p3=gST->tables[i].table;n3++;}
  if(eq(&gST->tables[i].guid,&sm2,16)){p2=gST->tables[i].table;n2++;}
 }
 if(n3>1||n2>1)return ERR(33);
 /* A present malformed 3.x entry is not hidden by falling back to 2.x. */
 if(n3? !capture(p3,3) : n2!=1||!capture(p2,2))return ERR(33);
 logtext("SMBIOS_BYTES=");loghex(meta.used,8);logtext(" CRC32=");loghex(meta.crc,8);logtext("\r\n");
 unsigned board=0,bios=0,id=0;const uint8_t *p=source,*end=p+meta.used;
 while(p<end){unsigned size=p[1];const uint8_t *q=p+size;while(q+1<end&&(q[0]||q[1]))q++;
  if(p[0]==0){if(size<=5||++bios!=1||!string_is(p+size,q+1,p[5],"3107"))return ERR(15);}
  if(p[0]==1){if(size<24||++id!=1||!eq(p+8,target_uuid,16))return ERR(15);}
  if(p[0]==2){if(size<=5||++board!=1||!string_is(p+size,q+1,p[5],"ROG MAXIMUS Z790 HERO"))return ERR(15);}
  p=q+2;
 }
 if(board!=1||bios!=1||id!=1)return ERR(15);
 logtext("IDENTITY=HERO / 3107 / .15 raw Type1 UUID exact\r\n");return 0;
}
