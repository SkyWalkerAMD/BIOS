/* QEMU-only fault injection DXE. Never include this in any hardware media. */
#include "efi_min.h"
#ifndef SEED_CASE
#define SEED_CASE 1
#endif
typedef ES(EA*GETVAR)(C16*,GUID*,uint32_t*,UN*,void*);
typedef ES(EA*SETVAR)(C16*,GUID*,uint32_t,UN,void*);
typedef struct {HDR hdr;void*a[6];GETVAR get;void*next;SETVAR set;} RT;
OFF(RT,get,0x48);OFF(RT,set,0x58);
static GETVAR old_get;static SETVAR old_set;static unsigned queries;
static GUID seed={0x1ce1e5bc,0x7ceb,0x42f2,{0x81,0xe5,0x8a,0xad,0xf1,0x80,0xf5,0x7b}};
static void trace(const char*s){while(*s){__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s),"Nd"((uint16_t)0x402));s++;}}
static int equal(const void*a,const void*b,UN n){const uint8_t*p=a,*q=b;for(UN i=0;i<n;i++)if(p[i]!=q[i])return 0;return 1;}
static ES EA get(C16*n,GUID*g,uint32_t*a,UN*s,void*b){
 C16 name[]=L"RandomSeed";
 if(!n||!g||!equal(g,&seed,16)||!equal(n,name,sizeof(name)))return old_get(n,g,a,s,b);
 if(!s||*s||b||a){trace("LC01_TEST_SEED_CONTENT_REQUEST_FORBIDDEN\n");return ERR(26);}
 queries++;trace("LC01_TEST_SEED_QUERY\n");
 if((SEED_CASE==3||SEED_CASE==4)&&queries==1)return ERR(14);
 if(SEED_CASE==1||SEED_CASE==3){*s=32;return ERR(5);}
 if(SEED_CASE==2||SEED_CASE==4)return ERR(7);
 if(SEED_CASE==5){*s=32;return ERR(14);}
 return 0;
}
static ES EA set(C16*n,GUID*g,uint32_t a,UN s,void*b){if(queries){trace("LC01_TEST_FORBIDDEN_SET_VARIABLE\n");return ERR(26);}return old_set(n,g,a,s,b);}
ES EA efi_main(HANDLE self,ST*st){
 (void)self;uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));
 if(b!=0x54474354U||c!=0x43544743U||d!=0x47435447U)return ERR(3);
 if(!st||!st->rt||!st->bs)return ERR(2);RT*rt=st->rt;old_get=rt->get;old_set=rt->set;rt->get=get;rt->set=set;
 rt->hdr.crc=0;typedef ES(EA*CRC)(void*,UN,uint32_t*);ES e=((CRC)st->bs->crc32)(rt,rt->hdr.size,&rt->hdr.crc);trace("LC01_TEST_SEED_FIXTURE_INSTALLED\n");return e;
}
