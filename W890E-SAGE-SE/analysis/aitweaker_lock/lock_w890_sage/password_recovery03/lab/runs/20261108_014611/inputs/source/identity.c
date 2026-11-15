#include "recovery.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID sm2={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0,0x90,0x27,0x3f,0xc1,0x4d}};
static GUID sm3={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
typedef struct {GUID guid;uint32_t image_size,entry,rva,text_size;uint8_t text_sha[32];} MODULE;
static const MODULE modules[]={
 {{0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}},2154496,4816,4096,174073,
 {0x49,0xad,0x95,0xff,0x56,0x45,0x19,0xfd,0xdf,0x96,0x62,0x71,0xe9,0x78,0x01,0x6a,0x5b,0xc5,0x18,0xa4,0x88,0xb3,0xb6,0x12,0xbd,0xc7,0x93,0xa0,0xc7,0x35,0xb1,0xd0}},
 {{0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}},909312,25728,4096,597466,
 {0xe0,0xb8,0x09,0x4c,0x48,0x2a,0x64,0x7d,0x71,0x96,0xd1,0x3a,0xa3,0xb0,0x59,0x90,0xd4,0x85,0x6d,0xc3,0x5d,0xe8,0xae,0xe1,0x03,0xb9,0xf9,0x35,0xfe,0x35,0xd9,0x58}}
};
static uint16_t u16(const uint8_t*p){return p[0]|((uint16_t)p[1]<<8);}
static uint32_t u32(const uint8_t*p){return u16(p)|((uint32_t)u16(p+2)<<16);}
static uint64_t u64(const uint8_t*p){return u32(p)|((uint64_t)u32(p+4)<<32);}
static int sumzero(const uint8_t*p,size_t n){uint8_t sum=0;while(n--)sum+=*p++;return !sum;}
static int string_is(const uint8_t *strings,size_t n,uint8_t index,const char *expected){
 if(!index)return 0;size_t pos=0;
 for(unsigned current=1;current<=index;current++){
  size_t end=pos;while(end<n&&strings[end])end++;
  if(end==n||end==pos)return 0;
  if(current==index){size_t i=0;while(expected[i])i++;return i==end-pos&&!memcmp(strings+pos,expected,i);}
  pos=end+1;
 }return 0;
}
int rc_parse_smbios(const uint8_t *table,size_t n){
 if(!table||n<6||n>1024*1024)return 0;unsigned board=0,bios=0;size_t pos=0;
 for(unsigned records=0;records<4096&&pos+4<=n;records++){
  uint8_t type=table[pos],length=table[pos+1];if(length<4||length>n-pos)return 0;
  size_t end=pos+length;while(end+1<n&&(table[end]||table[end+1]))end++;
  if(end+1>=n)return 0;const uint8_t *s=table+pos+length;size_t sn=end+2-(pos+length);
  if(type==0){if(length<0x12||++bios!=1||!string_is(s,sn,table[pos+5],"0603"))return 0;}
  if(type==2){if(length<8||++board!=1||!string_is(s,sn,table[pos+4],"ASUSTeK COMPUTER INC.")||
    !string_is(s,sn,table[pos+5],"Pro WS W890E-SAGE SE"))return 0;}
  if(type==127)return board==1&&bios==1;
  pos=end+2;
 }return 0;
}
static int board_identity(void){
 if(!rc_alive()||rc_st->table_count>512||!rc_present(rc_st->tables,rc_st->table_count*sizeof(CT),0))return 0;
 unsigned found=0;
 for(UN i=0;i<rc_st->table_count;i++){
  CT c=rc_st->tables[i];int kind=!memcmp(&c.guid,&sm3,16)?3:!memcmp(&c.guid,&sm2,16)?2:0;if(!kind)continue;
  const uint8_t *entry=c.table;if(!rc_present(entry,kind==3?24:31,0))return 0;
  uint64_t address;uint32_t n;
  if(kind==3){
   if(memcmp(entry,"_SM3_",5)||entry[6]!=24||entry[7]<3||!sumzero(entry,24))return 0;
   n=u32(entry+12);address=u64(entry+16);
  }else{
   if(memcmp(entry,"_SM_",4)||entry[5]!=31||memcmp(entry+16,"_DMI_",5)||!sumzero(entry,31)||!sumzero(entry+16,15))return 0;
   n=u16(entry+22);address=u32(entry+24);
  }
  if(!n||n>1024*1024||!rc_present((void *)(uintptr_t)address,n,0)||!rc_parse_smbios((void *)(uintptr_t)address,n))return 0;
  found++;
 }return found>=1&&found<=2;
}
static int fv_guid(void *path,GUID *guid){
 const uint8_t *p=path;unsigned matches=0;
 for(size_t pos=0;pos+4<=1024;){
  if(!rc_present(p+pos,4,0))return 0;uint16_t n=u16(p+pos+2);
  if(n<4||n>1024-pos||!rc_present(p+pos,n,0))return 0;
  if(p[pos]==0x7f)return p[pos+1]==0xff&&n==4&&matches==1;
  if(p[pos]==4&&p[pos+1]==6){if(n!=20||++matches!=1)return 0;memcpy(guid,p+pos+4,16);}
  pos+=n;
 }return 0;
}
int rc_module_matches(unsigned index,const void *base,size_t bytes){
 if(index>=2)return 0;const MODULE *m=&modules[index];const uint8_t*p=base;
 if(bytes!=m->image_size||!rc_present(p,4096,0)||u16(p)!=0x5a4d)return 0;
 size_t pe=u32(p+0x3c);if(pe>4096-24||u32(p+pe)!=0x4550||u16(p+pe+4)!=0x8664)return 0;
 unsigned count=u16(p+pe+6),options=u16(p+pe+20);size_t opt=pe+24;
 if(!count||count>96||options<0x70||options>4096-opt||u16(p+opt)!=0x20b||u32(p+opt+16)!=m->entry||u32(p+opt+56)!=m->image_size)return 0;
 size_t table=opt+options;if(count>(4096-table)/40)return 0;unsigned texts=0;
 for(unsigned i=0;i<count;i++){
  const uint8_t*s=p+table+40*i;
  if(!memcmp(s,".text\0\0\0",8)){if(++texts!=1||u32(s+8)!=m->text_size||u32(s+12)!=m->rva)return 0;}
 }
 if(texts!=1||!rc_present(p+m->rva,m->text_size,0))return 0;
 uint8_t digest[32];ap_sha256(p+m->rva,m->text_size,digest);int same=ap_constant_equal(digest,m->text_sha,32);ap_secure_zero(digest,32);return same;
}
static int module_identity(void){
 HANDLE *handles=0;UN count=0;ES s=rc_st->bs->locate_handles(2,&loaded_guid,0,&count,&handles);
 if(!rc_alive()||FAILED(s))return 0;
 if(!count||count>4096||!rc_present(handles,count*sizeof(*handles),0)){rc_release(handles);return 0;}
 unsigned matched[2]={0,0};int valid=1;
 for(UN i=0;i<count&&valid;i++){
  if(!rc_alive()||!rc_present(handles,count*sizeof(*handles),0)){valid=0;break;}
  LOADED *li=0;s=rc_st->bs->handle_protocol(handles[i],&loaded_guid,(void **)&li);
  if(!rc_alive()||FAILED(s)||!rc_present(li,sizeof(*li),0)){valid=0;break;}
  GUID guid;if(!fv_guid(li->filepath,&guid))continue;
  for(unsigned module=0;module<2;module++)if(!memcmp(&guid,&modules[module].guid,16)){
   if(++matched[module]!=1||li->revision!=0x1000||!rc_module_matches(module,li->image_base,li->image_size))valid=0;
  }
 }
 rc_release(handles);return rc_alive()&&valid&&matched[0]==1&&matched[1]==1;
}
uint32_t rc_identity(void){
 if(!rc_alive())return 0;uint32_t bits=board_identity()?1U:0U;
 if(rc_alive()&&module_identity())bits|=2U;return rc_alive()?bits:0;
}
