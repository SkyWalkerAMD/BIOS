/* Pure bounded PI section parser. ABI/format from EDK2 PiFirmwareFile.h. */
#include "fw_sections.h"
static uint32_t r32(const uint8_t *p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static int pad(const uint8_t *p,size_t n){while(n--){if(*p!=0&&*p!=0xff)return 0;p++;}return 1;}
int fp_sections_parse(const uint8_t *p,size_t n,FP_SECTIONS *out){
 if(out){out->count=0;out->pe_count=0;out->encapsulated=0;}
 if(!p||!out||!n||n>1048576)return FP_SECT_ARGUMENT;
 size_t at=0;
 while(at<n){
  if(n-at<4)return pad(p+at,n-at)?FP_SECT_OK:FP_SECT_PADDING;
  if(out->count>=64)return FP_SECT_LIMIT;
  uint32_t size=(uint32_t)p[at]|((uint32_t)p[at+1]<<8)|((uint32_t)p[at+2]<<16),header=4;
  if(size==0xffffff){if(n-at<8)return FP_SECT_HEADER;size=r32(p+at+4);header=8;}
  if(size<header||size>n-at)return FP_SECT_LENGTH;
  FP_SECTION *s=&out->items[out->count++];
  *s=(FP_SECTION){(uint32_t)at,size,(uint32_t)at+header,size-header,p[at+3]};
  if(s->type==0x10)out->pe_count++;
  if(s->type==1||s->type==2)out->encapsulated++;
  size_t end=at+size,next=(end+3)&~(size_t)3;
  if(next>n)return pad(p+end,n-end)?FP_SECT_OK:FP_SECT_PADDING;
  if(!pad(p+end,next-end))return FP_SECT_PADDING;
  at=next;
 }
 return FP_SECT_OK;
}
