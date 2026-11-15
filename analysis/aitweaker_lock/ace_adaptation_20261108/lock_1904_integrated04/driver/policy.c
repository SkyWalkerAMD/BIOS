#include "lock.h"
#include "policy_data.h"
int policy_form(uint16_t form) {
 for(size_t i=0;i<sizeof(protected_forms)/sizeof(protected_forms[0]);i++)if(form==protected_forms[i])return 1;
 return 0;
}
int policy_question(uint16_t q) {
 for(size_t i=0;i<sizeof(protected_questions)/sizeof(protected_questions[0]);i++)if(q==protected_questions[i])return 1;
 return 0;
}
int policy_inert_ifr(const uint8_t *ifr,UN size) {
 if(!ifr || size!=17)return 0;
 for(size_t i=0;i<sizeof(inert_exit_questions)/sizeof(inert_exit_questions[0]);i++)
  if(!memcmp(ifr,inert_exit_questions[i],17))return 1;
 return 0;
}
static uint32_t get32(const uint8_t *p) {return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static uint16_t get16(const uint8_t *p) {return (uint16_t)(p[0]|((uint16_t)p[1]<<8));}
static void put16(uint8_t *p,uint16_t v) {p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static void put32(uint8_t *p,uint32_t v) {for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static int question_op(uint8_t op) {return op==5 || op==6 || op==7 || op==8 || op==12 || op==15 || op==0x1a || op==0x1b || op==0x1c || op==0x23;}
static void action(uint8_t *p,uint16_t prompt,uint16_t help,uint16_t qid) {
 const uint8_t bytes[15]={0x0c,15,0,0,0,0,0,0,0,0,0xff,0xff,4,0,0};
 memcpy(p,bytes,15);put16(p+2,prompt);put16(p+4,help);put16(p+6,qid);
}
/* Two-pass bounded transformation. No partial output on malformed input.
 * This only adds management actions. Page access is enforced by the driver. */
int policy_ifr_insert(const uint8_t *src,UN n,uint16_t set_prompt,uint16_t set_help,
 uint16_t clear_prompt,uint16_t clear_help,uint8_t *dst,UN capacity,UN *written) {
 static const uint8_t setup_formset[16]={0x4a,0x10,0x59,0x7b,0x0d,0xc0,0x58,0x41,0x87,0xff,0xf0,0x4d,0x63,0x96,0xa9,0x15};
 UN insert=0,form_package=0,found=0,package_end=0;
 if(written)*written=0;
 if(!src || !dst || !written || n<24 || n>4*1024*1024 || capacity<n+30 || get32(src+16)!=n || src==dst)return 0;
 if(!set_prompt || !set_help || !clear_prompt || !clear_help)return 0;
 for(UN p=20;p<n;) {
  if(n-p<4)return 0;
  uint32_t header=get32(src+p),length=header&0xffffffu;uint8_t type=(uint8_t)(header>>24);
  if(length<4 || length>n-p)return 0;
  if(type==0xdf) {if(length!=4 || p+length!=n)return 0;package_end=1;}
  if(type==2) {
   uint8_t stack[64];unsigned depth=0;int target_set=-1,target_form=-1;
   for(UN q=p+4;q<p+length;) {
    if(p+length-q<2)return 0;
    uint8_t op=src[q],size=src[q+1]&0x7f,scope=src[q+1]>>7;
    if(size<2 || size>p+length-q)return 0;
    if(question_op(op)) {
     if(size<13)return 0;
     if(get16(src+q+6)==LOCK_QID || get16(src+q+6)==LOCK_CLEAR_QID)return 0;
    }
    if(op==0x0e) {
     if(size<23 || !scope || target_set>=0)return 0;
     if(!memcmp(src+q+2,setup_formset,16))target_set=(int)depth;
    }
    if(op==1) {
     if(size<6 || !scope || target_form>=0)return 0;
     if(target_set>=0 && get16(src+q+2)==0x271e)target_form=(int)depth;
    }
    if(op==0x29) {
     if(size!=2 || scope || !depth)return 0;
     depth--;
     if((int)depth==target_form) {
      if(stack[depth]!=1)return 0;
      insert=q;form_package=p;found++;target_form=-1;
     }
     if((int)depth==target_set) {if(stack[depth]!=0x0e)return 0;target_set=-1;}
    } else if(scope) {if(depth>=sizeof(stack))return 0;stack[depth++]=op;}
    q+=size;
   }
   if(depth || target_set>=0 || target_form>=0)return 0;
  }
  p+=length;
 }
 if(!package_end || found!=1 || !insert || !form_package)return 0;
 memcpy(dst,src,(size_t)insert);action(dst+insert,set_prompt,set_help,LOCK_QID);
 action(dst+insert+15,clear_prompt,clear_help,LOCK_CLEAR_QID);
 memcpy(dst+insert+30,src+insert,(size_t)(n-insert));
 put32(dst+16,(uint32_t)n+30);put32(dst+form_package,get32(src+form_package)+30);
 *written=n+30;return 1;
}
