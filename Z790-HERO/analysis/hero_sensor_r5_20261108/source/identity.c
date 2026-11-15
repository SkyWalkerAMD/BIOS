/* Local identity only. No hard-coded UUID/serial or copied donor strings.
 * Validate the entire SMBIOS stream through Type 127 before using any field.
 * All firmware pointers must be contained in the current readable RAM map. */
#include "r2.h"
LOCAL_IDENTITY local_identity;
static uint8_t memory_map[131072];
static UN map_bytes,map_stride;
uint32_t identity_crc(const void *data,size_t n){
 const uint8_t *p=data;uint32_t crc=0xffffffffU;
 while(n--){crc^=*p++;for(unsigned k=0;k<8;k++)crc=(crc>>1)^(0xedb88320U&(0U-(crc&1)));}
 return ~crc;
}
static int checksum(const uint8_t *p,size_t n){uint8_t sum=0;while(n--)sum+=*p++;return !sum;}
static int string_at(const uint8_t *p,const uint8_t *end,uint8_t id,char *out,UN cap){
 if(!id||!cap)return 0;
 for(unsigned index=1;p<end&&*p;index++){
  const uint8_t *q=p;while(q<end&&*q)q++;if(q==end)return 0;
  if(index==id){UN n=(UN)(q-p);if(!n||n>=cap)return 0;
   for(UN j=0;j<n;j++){if(p[j]<32||p[j]>126)return 0;out[j]=(char)p[j];}out[n]=0;return 1;
  }p=q+1;
 }return 0;
}
static int date_valid(const char *d){
 for(unsigned i=0;i<10;i++){if(i==2||i==5){if(d[i]!='/')return 0;}else if(d[i]<'0'||d[i]>'9')return 0;}
 if(d[10])return 0;
 unsigned m=(d[0]-'0')*10+d[1]-'0',day=(d[3]-'0')*10+d[4]-'0';
 unsigned y=(d[6]-'0')*1000+(d[7]-'0')*100+(d[8]-'0')*10+d[9]-'0';
 static const uint8_t days[12]={31,28,31,30,31,30,31,31,30,31,30,31};
 if(m<1||m>12||y<1900)return 0;
 unsigned max=days[m-1]+(m==2&&y%4==0&&(y%100!=0||y%400==0));return day>=1&&day<=max;
}
static UN put_string(uint8_t *out,UN at,const char *s){do{out[at++]=(uint8_t)*s;}while(*s++);return at;}
ES identity_parse(const uint8_t *table,UN length,LOCAL_IDENTITY *out){
 if(!table||!out||length<6||length>262144)return ERR(2);
 LOCAL_IDENTITY v;memset(&v,0,sizeof(v));
 UN at=0;unsigned count0=0,count2=0,records=0;int ended=0,extras=1;
 while(at<length){
  if(length-at<6||++records>8192)return ERR(33);
  const uint8_t *p=table+at;UN size=p[1];if(size<4||size>length-at-2)return ERR(33);
  UN q=at+size;while(q+1<length&&(table[q]||table[q+1]))q++;
  if(q+1>=length)return ERR(33);
  const uint8_t *end=table+q+1;
  if(p[0]==0){
   if(++count0!=1||size<6||!string_at(p+size,end,p[5],v.bios,sizeof(v.bios)))return ERR(33);
   if(size<9||!string_at(p+size,end,p[8],v.date,sizeof(v.date)))extras=0;
  }else if(p[0]==2){
   if(++count2!=1||size<6||!string_at(p+size,end,p[5],v.model,sizeof(v.model)))return ERR(33);
   if(size<8||!string_at(p+size,end,p[4],v.manufacturer,sizeof(v.manufacturer))||
      !string_at(p+size,end,p[6],v.revision,sizeof(v.revision))||!string_at(p+size,end,p[7],v.serial,sizeof(v.serial)))extras=0;
  }
  at=q+2;if(p[0]==127){if(size!=4)return ERR(33);ended=1;break;}
 }
 if(!ended||count0!=1||count2!=1)return ERR(33);
 for(unsigned i=0;i<4;i++)if(v.bios[i]<'0'||v.bios[i]>'9')return ERR(33);
 if(v.bios[4])return ERR(33);
 v.table_bytes=(uint32_t)at;v.table_crc=identity_crc(table,at);
 /* Missing optional identity fields block only Dashboard, not sensor identity. */
 if(!extras||!date_valid(v.date)){*out=v;return 0;}
 v.bios_request[0]=0;UN n=put_string(v.bios_request,1,v.bios);n=put_string(v.bios_request,n,v.date);
 if(n!=17)return ERR(33);v.bios_bytes=(uint32_t)n;
 v.board_request[0]=2;n=put_string(v.board_request,1,v.manufacturer);n=put_string(v.board_request,n,v.model);
 n=put_string(v.board_request,n,v.revision);n=put_string(v.board_request,n,v.serial);
 if(n>sizeof(v.board_request))return ERR(33);v.board_bytes=(uint32_t)n;
 v.dashboard_valid=1;*out=v;return 0;
}
static int readable(UN address,UN length){
 if(!address||!length||address+length<address)return 0;UN end=address+length;
 while(address<end){UN next=address;
  for(UN at=0;at<map_bytes;at+=map_stride){const uint8_t *d=memory_map+at;
   uint32_t type=u32(d);UN start=u64(d+8),pages=u64(d+24);
   if(!((type>=1&&type<=7)||type==9||type==10)||!pages||pages>(~(UN)0-start)/4096)continue;
   UN limit=start+pages*4096;
   if(start<=address&&address<limit&&limit>next)next=limit;
  }
  if(next==address)return 0;address=next<end?next:end;
 }return 1;
}
ES identity_read(void){
 static GUID s3={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
 static GUID s2={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0x00,0x90,0x27,0x3f,0xc1,0x4d}};
 memset(&local_identity,0,sizeof(local_identity));
 if(!gST||!gST->bs||!gST->bs->get_memory_map||gST->table_count>1024)return ERR(2);
 UN key=0;uint32_t version=0;map_bytes=sizeof(memory_map);map_stride=0;
 ES e=gST->bs->get_memory_map(&map_bytes,memory_map,&key,&map_stride,&version);
 if(e||map_bytes>sizeof(memory_map)||map_stride<40||map_stride>256||map_stride%8||!map_bytes||map_bytes%map_stride||version!=1)return e?e:ERR(33);
 if(!gST->table_count||!readable((UN)gST->tables,gST->table_count*sizeof(CT)))return ERR(33);
 const uint8_t *table=0;UN length=0;
 for(unsigned pass=0;pass<2&&!table;pass++)for(UN i=0;i<gST->table_count;i++){
  CT *t=&gST->tables[i];if(!eq(&t->guid,pass?&s2:&s3,16))continue;
  const uint8_t *p=t->table;UN min=pass?31:24;
  if(!readable((UN)p,min))return ERR(33);UN entry=pass?p[5]:p[6];
  if(entry<min||entry>64||!readable((UN)p,entry)||!checksum(p,entry))return ERR(33);
  if(!pass){if(!eq(p,"_SM3_",5))return ERR(33);table=(void *)(UN)u64(p+16);length=u32(p+12);}
  else{if(!eq(p,"_SM_",4)||!eq(p+16,"_DMI_",5)||!checksum(p+16,15))return ERR(33);table=(void *)(UN)u32(p+24);length=u16(p+22);}
  break;
 }
 if(!table||length<6||length>262144||!readable((UN)table,length))return ERR(33);
 e=identity_parse(table,length,&local_identity);
 if(!e){r3_report.source_crc=local_identity.table_crc;r3_report.source_bytes=local_identity.table_bytes;}
 return e;
}
void detect_board(void){
 report.board[0]=report.bios[0]=0;r3_report.source_status=identity_read();
 if(!r3_report.source_status){strcopy(report.board,sizeof(report.board),local_identity.model);strcopy(report.bios,sizeof(report.bios),local_identity.bios);}
}
