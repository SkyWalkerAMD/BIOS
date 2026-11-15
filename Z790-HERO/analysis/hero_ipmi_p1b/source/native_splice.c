#include "native.h"
static const GUID target={0x7b59104a,0xc00d,0x4158,{0x87,0xff,0xf0,0x4d,0x63,0x96,0xa9,0x15}};
static uint32_t crc(const uint8_t *p,size_t n){uint32_t r=0xffffffffU;while(n--){r^=*p++;for(unsigned j=0;j<8;j++)r=(r>>1)^(0xedb88320U & (0U-(r&1)));}return ~r;}
int native_form_bounds(const uint8_t *b,size_t n,size_t *insert,size_t *endset){
 if(!b||!insert||!endset||n<50||n>1048576||b[3]!=2||(u32(b)&0xffffffU)!=n)return 0;
 unsigned depth=0,found=0,forms=0;size_t advanced=0,lastend=0;unsigned advdepth=0;
 for(size_t p=4;p<n;){
  if(n-p<2)return 0;uint8_t op=b[p],len=b[p+1]&127,scope=b[p+1]>>7;
  if(len<2||len>n-p)return 0;
  if((op==5||op==6||op==7||op==8||op==0xc||op==0xf||op==0x1c||op==0x23)&&len>=13){
   uint16_t qid=u16(b+p+6);if(qid>=0xe100&&qid<=0xe120)return 0;
  }
  if(op==0xe){if(len<23||depth||forms++||!eq(b+p+2,&target,16))return 0;}
  if(op==1){
   if(len!=6||depth<1||!scope)return 0;uint16_t id=u16(b+p+2);
   if(id>=0xe100&&id<=0xe104)return 0;
   if(id==10005){if(depth!=1||found||advanced)return 0;advanced=p;advdepth=depth+1;}
  }
  if(op==0x29){
   if(len!=2||scope||!depth)return 0;
   if(advanced&&depth==advdepth){
    size_t length=p+2-advanced;
    if(length!=1140||crc(b+advanced,length)!=0x236a962eU)return 0;
    *insert=p;found++;advanced=0;
   }
   if(depth==1)lastend=p;
   depth--;
  }else if(scope){if(depth>=64)return 0;depth++;}
  p+=len;
 }
 if(depth||forms!=1||found!=1||lastend!=n-2)return 0;*endset=lastend;return 1;
}
int native_splice(const uint8_t *b,size_t n,const uint8_t *extra,size_t extra_n,uint16_t title,uint16_t help,uint8_t *out,size_t cap,size_t *used){
 size_t at,end;if(!out||!used||!extra||!extra_n||extra_n>65536||!title||!help||!native_form_bounds(b,n,&at,&end))return 0;
 size_t total=n+15+extra_n;if(total>cap||total>=0x1000000)return 0;
 uint8_t ref[15]={0x0f,15,(uint8_t)title,(uint8_t)(title>>8),(uint8_t)help,(uint8_t)(help>>8),0,0xe1,0,0,0,0,0,0,0xe1};
 memcpy(out,b,at);memcpy(out+at,ref,15);memcpy(out+at+15,b+at,end-at);
 memcpy(out+end+15,extra,extra_n);memcpy(out+end+15+extra_n,b+end,n-end);
 out[0]=(uint8_t)total;out[1]=(uint8_t)(total>>8);out[2]=(uint8_t)(total>>16);*used=total;return 1;
}
