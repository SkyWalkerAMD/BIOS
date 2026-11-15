#include "hero_inventory_catalog.h"

typedef struct { const uint8_t *p; uint32_t n; } SPAN;
typedef struct {
 const uint8_t *table; uint32_t bytes; HIC_CATALOG *out; HIC_SCRATCH *work;
 int error; uint32_t where, cursor; unsigned fields;
} CTX;
static void clear(void *p,size_t n){uint8_t *v=(uint8_t*)p;while(n--)*v++=0;}
static void copy(void *to,const void *from,size_t n){uint8_t *a=to;const uint8_t *b=from;while(n--)*a++=*b++;}
static uint32_t length(const char *s){uint32_t n=0;while(s[n])n++;return n;}
static int err(CTX *c,int code,uint32_t at){if(!c->error){c->error=code;c->where=at;}return 0;}
static int overlaps(const void *a,size_t an,const void *b,size_t bn){
 uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
 if(an>UINTPTR_MAX-x||bn>UINTPTR_MAX-y)return 1;
 return x<y+bn&&y<x+an;
}
static int utf8(const uint8_t *s,uint32_t n,uint32_t *used,uint32_t *cp){
 if(!n)return 0;uint32_t x=s[0],k=1,v=x,min=0;
 if(x<128){*used=1;*cp=x;return 1;}
 if(x>=0xc2&&x<=0xdf){k=2;v=x&31;min=128;}
 else if(x>=0xe0&&x<=0xef){k=3;v=x&15;min=2048;}
 else if(x>=0xf0&&x<=0xf4){k=4;v=x&7;min=65536;}else return 0;
 if(n<k)return 0;for(uint32_t i=1;i<k;i++){if((s[i]&0xc0)!=0x80)return 0;v=(v<<6)|(s[i]&63);}
 if(v<min||v>0x10ffff||(v>=0xd800&&v<=0xdfff))return 0;
 *used=k;*cp=v;return 1;
}
static int whitespace(uint32_t x){
 return x==32||(x>=9&&x<=13)||(x>=0x1c&&x<=0x1f)||x==0x85||x==0xa0||x==0x1680||
        (x>=0x2000&&x<=0x200a)||x==0x2028||x==0x2029||x==0x202f||x==0x205f||x==0x3000;
}
static int placeholders(SPAN s){
 static const char *const list[]={"default string","to be filled by o.e.m.","to be filled by oem",
  "system product name","system manufacturer","system serial number","system version",
  "not specified","not applicable","unknown","none","sku"};
 for(unsigned i=0;i<sizeof(list)/sizeof(list[0]);i++){
  if(length(list[i])!=s.n)continue;uint32_t j=0;
  while(j<s.n){uint8_t x=s.p[j];if(x>='A'&&x<='Z')x+=32;if(x!=(uint8_t)list[i][j])break;j++;}
  if(j==s.n)return 1;
 }return 0;
}
static SPAN str(CTX *c,const HIC_RECORD *r,uint32_t field){
 SPAN none={0,0};if(field>=r->length||!c->table[r->offset+field])return none;
 uint32_t want=c->table[r->offset+field],p=r->strings_begin,index=1;
 while(p<r->strings_end){
  uint32_t end=p;while(end<r->strings_end&&c->table[end])end++;
  if(index==want){
   uint32_t begin=p,last=p,at=p,k=0,cp=0;int leading=1;
   while(at<end){
    if(!utf8(c->table+at,end-at,&k,&cp)){err(c,HIC_STRING_ENCODING,at);return none;}
    if(leading&&whitespace(cp))begin=at+k;else{leading=0;if(!whitespace(cp))last=at+k;}
    at+=k;
   }
   if(last<begin)last=begin;SPAN value={c->table+begin,last-begin};
   at=begin;while(at<last){utf8(c->table+at,last-at,&k,&cp);if(cp<32||cp==127){err(c,HIC_STRING_ENCODING,at);return none;}at+=k;}
   if(!value.n||placeholders(value)){c->out->warnings|=HIC_PLACEHOLDER_OMITTED;return none;}return value;
  }
  p=end+1;index++;
 }
 err(c,HIC_STRING_INDEX,r->offset+field);return none;
}
static int num(CTX *c,const HIC_RECORD *r,uint32_t offset,uint32_t width,uint32_t *value){
 if(offset>r->length||width>r->length-offset)return 0;uint32_t n=0;
 for(uint32_t i=0;i<width;i++)n|=(uint32_t)c->table[r->offset+offset+i]<<(8*i);*value=n;return 1;
}
static int scan(CTX *c){
 uint32_t p=0;HIC_SCRATCH *w=c->work;
 while(p<c->bytes){
  if(c->bytes-p<6)return err(c,HIC_STRUCTURE,p);
  uint8_t type=c->table[p],size=c->table[p+1];uint16_t handle=(uint16_t)(c->table[p+2]|c->table[p+3]<<8);
  if(size<4||(uint32_t)size+2>c->bytes-p)return err(c,HIC_STRUCTURE,p);
  /* Minimum base layouts for the types consumed below. Optional later fields
   * may be absent, but a header-only CPU/DIMM is not a usable inventory item. */
  if((type==0&&size<18)||(type==1&&size<25)||(type==2&&size<8)||
     (type==4&&size<26)||(type==17&&size<21))return err(c,HIC_STRUCTURE,p);
  if(w->handles[handle>>3]&(1u<<(handle&7)))return err(c,HIC_DUPLICATE_HANDLE,p);
  w->handles[handle>>3]|=(uint8_t)(1u<<(handle&7));
  if(++w->record_count>HIC_MAX_RECORDS)return err(c,HIC_LIMIT,p);
  uint32_t begin=p+size,end=begin;
  while(end+1<c->bytes&&(c->table[end]||c->table[end+1]))end++;
  if(end+1>=c->bytes)return err(c,HIC_STRUCTURE,begin);
  uint32_t at=begin,string_start=begin,k=0,cp=0;
  while(at<end){
   if(!c->table[at]){if(at-string_start>HIC_MAX_STRING)return err(c,HIC_LIMIT,string_start);string_start=++at;continue;}
   if(!utf8(c->table+at,end-at,&k,&cp))return err(c,HIC_STRING_ENCODING,at);at+=k;
  }
  if(end-string_start>HIC_MAX_STRING)return err(c,HIC_LIMIT,string_start);
  HIC_RECORD r={p,begin,end,handle,type,size};
  if(type==0){if(w->bios_count++)return err(c,HIC_AMBIGUOUS_TYPE,p);w->bios=r;}
  if(type==1){if(w->system_count++)return err(c,HIC_AMBIGUOUS_TYPE,p);w->system=r;}
  if(type==2){if(w->board_count++)return err(c,HIC_AMBIGUOUS_TYPE,p);w->board=r;}
  if(type==4){if(w->cpu_count>=HIC_MAX_CPUS)return err(c,HIC_LIMIT,p);w->cpus[w->cpu_count++]=r;}
  if(type==17){if(w->dimm_count>=HIC_MAX_DIMMS)return err(c,HIC_LIMIT,p);w->dimms[w->dimm_count++]=r;}
  p=end+2;
  if(type==127){
   if(size!=4||end!=begin||p!=c->bytes)return err(c,HIC_STRUCTURE,r.offset);
   if(!w->bios_count||!w->system_count||!w->board_count||!w->cpu_count||!w->dimm_count)return err(c,HIC_MISSING_TYPE,p);
   return 1;
  }
 }
 return err(c,HIC_STRUCTURE,p);
}
static void byte(CTX *c,char v){
 if(c->error)return;if(c->cursor>=HIC_JSON_BYTES){err(c,HIC_JSON_OVERFLOW,c->where);return;}c->out->json[c->cursor++]=v;
}
static void text(CTX *c,const char *s){while(*s)byte(c,*s++);}
static void hex4(CTX *c,uint32_t n){static const char hex[]="0123456789abcdef";text(c,"\\u");for(int i=12;i>=0;i-=4)byte(c,hex[(n>>i)&15]);}
static void quoted(CTX *c,SPAN s){
 byte(c,'"');uint32_t at=0,k=0,cp=0;
 while(at<s.n){
  if(!utf8(s.p+at,s.n-at,&k,&cp)){err(c,HIC_STRING_ENCODING,c->where);break;}at+=k;
  if(cp=='"'||cp=='\\'){byte(c,'\\');byte(c,(char)cp);}
  else if(cp<32||cp==127){err(c,HIC_STRING_ENCODING,c->where);break;}
  else if(cp<127)byte(c,(char)cp);
  else if(cp<=0xffff)hex4(c,cp);
  else{cp-=0x10000;hex4(c,0xd800+(cp>>10));hex4(c,0xdc00+(cp&1023));}
 }
 byte(c,'"');
}
static void key(CTX *c,const char *s){if(c->fields++)byte(c,',');SPAN v={(const uint8_t*)s,length(s)};quoted(c,v);byte(c,':');}
static void uint_json(CTX *c,uint32_t n){char rev[10];uint32_t count=0;do{rev[count++]=(char)('0'+n%10);n/=10;}while(n);while(count)byte(c,rev[--count]);}
static void prop(CTX *c,const char *name,SPAN s){if(s.n){key(c,name);quoted(c,s);}}
static void literal(CTX *c,const char *name,const char *s){SPAN v={(const uint8_t*)s,length(s)};prop(c,name,v);}
static void number(CTX *c,const char *name,uint32_t n){key(c,name);uint_json(c,n);}
static void state(CTX *c,const char *s){key(c,"Status");text(c,"{\"State\":");SPAN v={(const uint8_t*)s,length(s)};quoted(c,v);byte(c,'}');}
static void string_field(CTX *c,const HIC_RECORD *r,const char *name,uint32_t offset){prop(c,name,str(c,r,offset));}
static HIC_ITEM *start_item(CTX *c,uint32_t kind,uint32_t index,const HIC_RECORD *r){
 if(c->out->item_count>=HIC_MAX_ITEMS){err(c,HIC_LIMIT,r->offset);return 0;}
 HIC_ITEM *item=&c->out->items[c->out->item_count++];
 item->kind=kind;item->index=index;item->json_offset=c->cursor;item->source_offset=r->offset;item->source_handle=r->handle;
 c->where=r->offset;c->fields=0;byte(c,'{');return item;
}
static void end_item(CTX *c,HIC_ITEM *item){
 byte(c,'}');if(item)item->json_bytes=c->cursor-item->json_offset;byte(c,0);
}
static void fixed_text(char *dest,SPAN s){if(s.n)copy(dest,s.p,s.n);dest[s.n]=0;}
static int identity(CTX *c,uint8_t major,uint8_t minor){
 HIC_SCRATCH *w=c->work;SPAN bios=str(c,&w->bios,5),board=str(c,&w->board,5),bm=str(c,&w->board,4);
 SPAN model=str(c,&w->system,5),manufacturer=str(c,&w->system,4);
 if(c->error)return 0;
 if(!bios.n||!board.n)return err(c,HIC_IDENTITY_UNAVAILABLE,w->bios.offset);
 if(!model.n)model=board;if(!manufacturer.n)manufacturer=bm;
 if(!manufacturer.n)return err(c,HIC_IDENTITY_UNAVAILABLE,w->system.offset);
 fixed_text(c->out->bios_version,bios);fixed_text(c->out->board_model,board);fixed_text(c->out->board_manufacturer,bm);
 if(w->system.length<24)return err(c,HIC_UUID_UNAVAILABLE,w->system.offset);
 const uint8_t *u=c->table+w->system.offset+8;unsigned z=0,f=0;
 for(unsigned i=0;i<16;i++){z+=u[i]==0;f+=u[i]==255;}
 if(z==16||f==16)return err(c,HIC_UUID_UNAVAILABLE,w->system.offset+8);
 static const uint8_t le[]={3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
 static const char hex[]="0123456789abcdef";uint32_t at=0;
 for(unsigned i=0;i<16;i++){
  if(i==4||i==6||i==8||i==10)c->out->uuid[at++]='-';
  uint8_t v=u[(major>2||(major==2&&minor>=6))?le[i]:i];
  c->out->uuid[at++]=hex[v>>4];c->out->uuid[at++]=hex[v&15];
 }c->out->uuid[at]=0;
 HIC_ITEM *item=start_item(c,HIC_SYSTEM_PATCH,0,&w->system);
 prop(c,"Model",model);prop(c,"Manufacturer",manufacturer);prop(c,"BiosVersion",bios);literal(c,"UUID",c->out->uuid);
 string_field(c,&w->system,"SerialNumber",7);string_field(c,&w->system,"SKU",25);end_item(c,item);return !c->error;
}
static int cpu_count(CTX *c,const HIC_RECORD *r,uint32_t small,uint32_t extended,uint32_t *value){
 uint32_t n=0;if(!num(c,r,small,1,&n)||!n){c->out->warnings|=HIC_UNKNOWN_CPU_COUNT;return 0;}
 if(n==255){uint32_t ex=0;if(num(c,r,extended,2,&ex))n=ex;} /* old short-only FF means255 */
 if(!n||n==65535){c->out->warnings|=HIC_UNKNOWN_CPU_COUNT;return 0;}*value=n;return 1;
}
static void id_fields(CTX *c,const char *prefix,uint32_t index){
 char id[32];uint32_t n=length(prefix);copy(id,prefix,n);
 if(index>=10)id[n++]=(char)('0'+index/10);id[n++]=(char)('0'+index%10);id[n]=0;
 literal(c,"Id",id);literal(c,"Name",id);
}
static void cpu(CTX *c,const HIC_RECORD *r,uint32_t index){
 HIC_ITEM *item=start_item(c,HIC_CPU_POST,index,r);uint32_t n=0;
 id_fields(c,"DevType1_CPU",index);
 string_field(c,r,"Socket",4);string_field(c,r,"Manufacturer",7);string_field(c,r,"Model",16);
 string_field(c,r,"SerialNumber",32);string_field(c,r,"PartNumber",34);
 if(num(c,r,5,1,&n)&&n==3){literal(c,"ProcessorType","CPU");literal(c,"ProcessorArchitecture","x86");}
 /* Type4 MaxSpeed is a socket/system capability. Deliberately never emitted. */
 if(cpu_count(c,r,35,42,&n))number(c,"TotalCores",n);
 if(cpu_count(c,r,36,44,&n))number(c,"TotalEnabledCores",n);
 if(cpu_count(c,r,37,46,&n))number(c,"TotalThreads",n);
 if(num(c,r,24,1,&n)){
  if(!(n&64))state(c,"Absent");else if((n&7)==1)state(c,"Enabled");else if((n&7)==2||(n&7)==3)state(c,"Disabled");
 }end_item(c,item);
}
static int memory_speed(CTX *c,const HIC_RECORD *r,uint32_t offset,uint32_t extended,uint32_t *out){
 uint32_t n=0;if(!num(c,r,offset,2,&n)||!n){c->out->warnings|=HIC_UNKNOWN_SPEED;return 0;}
 if(n==65535){
  if(!num(c,r,extended,4,&n)||!n){c->out->warnings|=HIC_UNKNOWN_SPEED;return 0;}
  if(n&0x80000000u){err(c,HIC_BAD_VALUE,r->offset+extended);return 0;}
 }
 *out=n;return 1;
}
static void memory(CTX *c,const HIC_RECORD *r,uint32_t index){
 HIC_ITEM *item=start_item(c,HIC_MEMORY_POST,index,r);uint32_t n=0,capacity=0;int known=0;
 id_fields(c,"DevType2_DIMM",index);
 string_field(c,r,"DeviceLocator",16);string_field(c,r,"Manufacturer",23);
 string_field(c,r,"SerialNumber",24);string_field(c,r,"PartNumber",26);
 if(num(c,r,12,2,&n)&&n!=65535){
  if(!n){known=1;state(c,"Absent");}
  else{
   state(c,"Enabled");
   if(n==32767){
    if(num(c,r,28,4,&capacity)){
     if(capacity&0x80000000u)err(c,HIC_BAD_VALUE,r->offset+28);
     else if(capacity)known=1;
    }
   }else if(n&32768){
    uint32_t kib=n&32767;
    if(kib&&kib%1024==0){known=1;capacity=kib/1024;}
    else c->out->warnings|=HIC_FRACTIONAL_MIB_OMITTED;
   }else{known=1;capacity=n;}
  }
 }
 if(known)number(c,"CapacityMiB",capacity);else c->out->warnings|=HIC_UNKNOWN_CAPACITY;
 if(num(c,r,18,1,&n)){
  const char *s=0;switch(n){case 0x0f:s="SDRAM";break;case 0x12:s="DDR";break;case 0x13:s="DDR2";break;
   case 0x18:s="DDR3";break;case 0x1a:s="DDR4";break;case 0x22:s="DDR5";break;default:break;}
  if(s)literal(c,"MemoryDeviceType",s);
 }
 if(num(c,r,40,1,&n)&&n==3)literal(c,"MemoryType","DRAM");
 if(num(c,r,8,2,&n)&&n&&n!=65535)number(c,"BusWidthBits",n);
 if(num(c,r,10,2,&n)&&n&&n!=65535)number(c,"DataWidthBits",n);
 if(memory_speed(c,r,21,84,&n)){key(c,"AllowedSpeedsMHz");byte(c,'[');uint_json(c,n);byte(c,']');}
 if(memory_speed(c,r,32,88,&n))number(c,"OperatingSpeedMhz",n);
 end_item(c,item);
}
static uint32_t crc32(const uint8_t *p,uint32_t n){
 uint32_t crc=0xffffffffu;while(n--){crc^=*p++;for(unsigned i=0;i<8;i++)crc=(crc>>1)^(0xedb88320u&((uint32_t)0-(crc&1)));}return ~crc;
}
int HeroInventoryBuild(const uint8_t *table,uint32_t bytes,uint8_t major,uint8_t minor,HIC_CATALOG *out,HIC_SCRATCH *scratch){
 if(!table||!out||!scratch||overlaps(table,bytes,out,sizeof(*out))||overlaps(table,bytes,scratch,sizeof(*scratch))||overlaps(out,sizeof(*out),scratch,sizeof(*scratch)))return HIC_ARGUMENT;
 clear(out,sizeof(*out));clear(scratch,sizeof(*scratch));out->version=1;
 CTX c={table,bytes,out,scratch,0,0,0,0};
 if(bytes<6||bytes>HIC_MAX_TABLE)err(&c,HIC_TABLE_BOUND,0);
 else if(major<2||major>3||minor>99)err(&c,HIC_BAD_VERSION,0);
 else if(scan(&c)&&identity(&c,major,minor)){
  for(uint32_t i=0;i<scratch->cpu_count&&!c.error;i++)cpu(&c,&scratch->cpus[i],i);
  for(uint32_t i=0;i<scratch->dimm_count&&!c.error;i++)memory(&c,&scratch->dimms[i],i);
 }
 if(c.error){uint32_t code=(uint32_t)c.error,where=c.where;clear(out,sizeof(*out));out->version=1;out->result=code;out->error_offset=where;return c.error;}
 out->valid=1;out->cpu_count=scratch->cpu_count;out->dimm_count=scratch->dimm_count;out->json_bytes=c.cursor;
 out->table_bytes=bytes;out->table_crc32=crc32(table,bytes);out->smbios_major=major;out->smbios_minor=minor;return HIC_OK;
}
uint32_t HeroInventoryCatalogSize(void){return (uint32_t)sizeof(HIC_CATALOG);}
uint32_t HeroInventoryScratchSize(void){return (uint32_t)sizeof(HIC_SCRATCH);}
