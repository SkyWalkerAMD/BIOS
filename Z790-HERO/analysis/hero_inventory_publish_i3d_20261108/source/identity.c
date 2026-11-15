/* Read-only .71 identity gate. Every network entry revalidates the same board,
 * BIOS version and raw Type1 UUID; no mutable network state authorizes a host. */
#include "network.h"
#include "smbios_bounded.h"
#include "target_identity.h"
#include "inventory_source.h"
static GUID sm3={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
static GUID sm2={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0x00,0x90,0x27,0x3f,0xc1,0x4d}};
static SM_ENTRY chosen;
static SM_TABLE meta;
static unsigned gate_status;
static uint8_t seen_uuid[16];
static const uint8_t *selected_table;
static int load_table(const uint8_t *p,unsigned kind){
 if(!p)return SM_ADDRESS;
 unsigned n=p[kind==3?6:5];if(n<(kind==3?24U:31U)||n>64)return SM_LENGTH;
 int e=smbios_entry(p,n,kind,&chosen);if(e)return e;
 selected_table=(const uint8_t *)(UN)chosen.address;
 return smbios_table(selected_table,chosen.bound,chosen.count,&meta);
}
static void text_string(const uint8_t *p,const uint8_t *end,unsigned id,char *out,size_t cap){
 if(!id||!cap)return;
 for(unsigned i=1;p<end&&*p;i++){
  const uint8_t *q=p;while(q<end&&*q)q++;if(q==end)return;
  if(i==id){size_t n=(size_t)(q-p);if(n>=cap)return;for(size_t j=0;j<n;j++){if(p[j]<32||p[j]>=127)return;out[j]=(char)p[j];}out[n]=0;return;}
  p=q+1;
 }
}
int i3_target_valid(void){
 report.board[0]=report.bios[0]=0;memset(seen_uuid,0,sizeof(seen_uuid));gate_status=SM_ARGUMENT;
 if(!gST||!gST->tables||!gST->table_count||gST->table_count>1024)return 0;
 const uint8_t *p3=0,*p2=0;unsigned count3=0,count2=0;
 for(UN i=0;i<gST->table_count;i++){
  CT *t=&gST->tables[i];if(eq(&t->guid,&sm3,16)){p3=t->table;count3++;}
  if(eq(&t->guid,&sm2,16)){p2=t->table;count2++;}
 }
 int e=SM_ADDRESS;
 if(count3==1)e=load_table(p3,3);
 if(e&&count2==1)e=load_table(p2,2);
 gate_status=(unsigned)e;if(e)return 0;
 if(meta.types[0]!=1||meta.types[1]!=1||meta.types[2]!=1){gate_status=SM_COUNT;return 0;}
 const uint8_t *p=selected_table,*end=p+meta.used;
 while(p<end){
  unsigned type=p[0],len=p[1];const uint8_t *q=p+len;
  while(q+1<end&&(q[0]||q[1]))q++;
  if(type==0&&len>5)text_string(p+len,q+1,p[5],report.bios,sizeof(report.bios));
  if(type==2&&len>5)text_string(p+len,q+1,p[5],report.board,sizeof(report.board));
  if(type==1){if(len<24){gate_status=SM_HEADER;return 0;}memcpy(seen_uuid,p+8,16);}
  p=q+2;if(type==127)break;
 }
 if(!same(report.board,"ROG MAXIMUS Z790 HERO")||!same(report.bios,"3107")){gate_status=0x101;return 0;}
 if(!eq(seen_uuid,target_uuid,16)){gate_status=0x102;return 0;}
 gate_status=0;return 1;
}
void i3_identity_log(void){
 int good=i3_target_valid();
 logtext("I3_BOARD=");logtext(report.board);logtext(" BIOS=");logtext(report.bios);logtext("\r\nI3_TYPE1_UUID_RAW=");logbytes(seen_uuid,16);
 status("I3_IDENTITY_STATUS",gate_status);status("I3_TARGET_71_VERIFIED",(ES)good);
 say(report.board);say(" BIOS ");say(report.bios);say("\r\n");
}
int i3_inventory_source_valid(void){
 if(!i3_target_valid()||chosen.major!=3||chosen.minor!=5)return 0;
 const uint8_t *p=selected_table,*end=p+meta.used;size_t used=0;
 while(p<end){
  unsigned type=p[0],len=p[1];const uint8_t *q=p+len;
  while(q+1<end&&(q[0]||q[1]))q++;
  if(type==0||type==1||type==2||type==4||type==17){
   size_t n=(size_t)(q+2-p);
   if(n>sizeof(inventory_source_records)-used||!eq(p,inventory_source_records+used,n))return 0;used+=n;
  }
  p=q+2;if(type==127)break;
 }
 return used==sizeof(inventory_source_records);
}
