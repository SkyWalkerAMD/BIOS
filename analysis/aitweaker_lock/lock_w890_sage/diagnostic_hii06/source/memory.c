#include "memory.h"
/* This is a bounded read-only adaptation of the earlier W790 walker. No W790
 * board/RVA/schema is reused. Physical table reads assume pre-virtual-map x64
 * identity mappings; nonidentity targets are refused. No PTE, CR0/3/4, PAT,
 * EFER, foreign permission or cache policy is changed by this component. */
#define UNMODELED_CR4 ((1ULL<<20)|(1ULL<<21)|(1ULL<<22)|(1ULL<<23)|(1ULL<<24))
static uint64_t u64(const void *p){uint64_t v;memcpy(&v,p,8);return v;}
static uint64_t msr(uint32_t n){uint32_t a,d;__asm__ volatile("rdmsr":"=a"(a),"=d"(d):"c"(n));return a|((uint64_t)d<<32);}
int i04_cpu(I04_CPU *e){
 uint32_t a,b,c,d;memset(e,0,sizeof(*e));
 __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(1),"c"(0));
 if(!(d&(1u<<5))||!(d&(1u<<16)))return 0; /* MSR and PAT */
 __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x80000000u),"c"(0));
 if(a<0x80000008u)return 0;
 __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x80000008u),"c"(0));
 e->physical_bits=a&255;
 __asm__ volatile("mov %%cr0,%0":"=r"(e->cr0));
 __asm__ volatile("mov %%cr3,%0":"=r"(e->cr3));
 __asm__ volatile("mov %%cr4,%0":"=r"(e->cr4));
 e->efer=msr(0xc0000080);e->pat=msr(0x277);
 return e->physical_bits>=32&&e->physical_bits<=52&&(e->cr0&1)&&
  (e->cr0&(1ULL<<31))&&(e->cr0&(1ULL<<16))&&(e->cr4&(1ULL<<5))&&
  (e->efer&(1ULL<<10))&&(e->efer&(1ULL<<11))&&!(e->cr4&UNMODELED_CR4);
}
static const I04_MD *descriptor(const I04_VM *v,uint64_t a){
 const I04_MD *found=0;
 for(UN at=0;at<v->bytes;at+=v->stride){const I04_MD *d=(void *)(v->map+at);
  if(a>=d->start&&a-d->start<d->pages*4096){if(found)return 0;found=d;}}
 if(found)for(UN at=0;at<v->bytes;at+=v->stride){const I04_MD *d=(void *)(v->map+at);
  if(d!=found&&d->start<found->start+found->pages*4096&&found->start<d->start+d->pages*4096)return 0;}
 return found;
}
int i04_readable(const I04_VM *v,uint64_t a,UN n){
 if(!v||!v->valid||v->ended||!n||a<4096||a>=(1ULL<<47)||n>(1ULL<<47)-a)return 0;
 while(n){const I04_MD *d=descriptor(v,a);if(!d||d->type<1||d->type>6||(d->attrs&0x2000))return 0;
  UN available=d->start+d->pages*4096-a,take=n<available?n:available;n-=take;a+=take;}
 return 1;
}
int i04_capture(I04_VM *v,ST *st){
 if(!v||!st||v->ended)return 0;
 if(v->st){
  /* Only the first EFI entry-supplied table is a bootstrap trust anchor.
   * Every later service boundary checks the saved pages BEFORE dereference. */
  if(v->st!=st||!i04_vm_current(v)||!i04_access(v,(uintptr_t)st,sizeof(*st),0,0)||
     !i04_access(v,(uintptr_t)v->bs,sizeof(*v->bs),0,0)||st->bs!=v->bs||v->bs->get_memory_map!=v->get_map||
     !i04_access(v,(uintptr_t)v->get_map,1,0,1)){v->valid=0;return 0;}
 }else{
  v->st=st;v->bs=st->bs;if(!v->bs||!v->bs->get_memory_map)return 0;v->get_map=v->bs->get_memory_map;
 }
 v->valid=0;
 UN n=sizeof(v->map),stride=0,key=0;uint32_t rev=0;
 ES s=v->get_map(&n,v->map,&key,&stride,&rev);
 if(v->ended||FAILED(s)||!n||n>sizeof(v->map)||stride<sizeof(I04_MD)||stride>256||n%stride||rev!=1)return 0;
 for(UN at=0;at<n;at+=stride){const I04_MD *d=(void *)(v->map+at);
  if(!d->pages||(d->start&4095)||d->pages>(UINT64_MAX-d->start)/4096)return 0;}
 v->bytes=n;v->stride=stride;v->key=key;
 if(!i04_cpu(&v->cpu))return 0;v->valid=1;
 if(!i04_access(v,(uintptr_t)st,sizeof(*st),0,0)||!i04_access(v,(uintptr_t)v->bs,sizeof(*v->bs),0,0)||st->bs!=v->bs||v->bs->get_memory_map!=v->get_map){v->valid=0;return 0;}
 return 1;
}
int i04_vm_current(const I04_VM *v){
 if(!v||!v->valid||v->ended)return 0;I04_CPU now;
 return i04_cpu(&now)&&!memcmp(&now,&v->cpu,sizeof(now));
}
int i04_walk(const I04_VM *v,uint64_t a,I04_PAGE *out){
 memset(out,0,sizeof(*out));if(!v||!v->valid||v->ended||a<4096||a>=(1ULL<<47))return 0;
 const I04_CPU *e=&v->cpu;uint64_t mask=((1ULL<<e->physical_bits)-1)&~4095ULL;
 uint64_t table=e->cr3&0x000ffffffffff000ULL;if(table&~mask)return 0;
 unsigned levels=(e->cr4&(1ULL<<12))?5:4,rw=1,nx=0,user=1;
 for(unsigned level=levels;level;level--){
  if((table&4095)||!i04_readable(v,table,4096))return 0;
  uint64_t x=u64((void *)(uintptr_t)(table+8*((a>>(12+9*(level-1)))&511)));
  if(!(x&1)||((x&0x000ffffffffff000ULL)&~mask))return 0;
  if(!(e->efer&(1ULL<<11))&&(x&(1ULL<<63)))return 0;
  rw&=(unsigned)(x>>1)&1;nx|=(unsigned)(x>>63);user&=(unsigned)(x>>2)&1;
  int leaf=level==1||((level==2||level==3)&&(x&128));
  if(level>3&&(x&128))return 0;
  if(leaf){uint64_t bytes=1ULL<<(12+9*(level-1));
   if(level>1&&(x&((bytes-1)&~8191ULL)))return 0;
   uint64_t physical=(x&mask&~(bytes-1))|(a&(bytes-1));if(physical!=a)return 0;
   *out=(I04_PAGE){physical,bytes,rw,nx,user,(unsigned)((x>>3)&3)|((unsigned)((x>>(level==1?7:12))&1)<<2)};return 1;}
  table=x&mask;
 }return 0;
}
int i04_access(const I04_VM *v,uint64_t a,UN n,int write,int execute){
 if(!i04_readable(v,a,n))return 0;
 uint64_t end=a+n;for(uint64_t p=a&~4095ULL;p<end;p+=4096){I04_PAGE page;
  if(!i04_walk(v,p,&page)||page.user||(write&&!page.rw)||(execute&&page.nx))return 0;}
 return 1;
}
