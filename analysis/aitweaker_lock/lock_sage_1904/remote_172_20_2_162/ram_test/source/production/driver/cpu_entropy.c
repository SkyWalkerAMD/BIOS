/* Hardware seed source for firmware lacking EFI_RNG_PROTOCOL.
 * Intel DRNG guide sections 3.3.2 and 5.3: test CPUID, check CF on every
 * RDSEED, retry with PAUSE. Exhaustion is an error, never a weak fallback.
 * https://www.intel.com/content/www/us/en/developer/articles/guide/intel-digital-random-number-generator-drng-software-implementation-guide.html
 */
#include "lock.h"
int cpu_entropy_supported(void) {
 uint32_t a,b,c,d;
 __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0),"c"(0));
 if(a<7)return 0;
 __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(7),"c"(0));
 return (b&(1u<<18))!=0;
}
int cpu_entropy(uint8_t *out,size_t n) {
 if(!out || !n || n>256)return 1;
 memset(out,0,n);
 if(!cpu_entropy_supported())return 1;
 for(size_t i=0;i<n;) {
  uint64_t value=0;uint8_t ok=0;
  for(unsigned retry=0;retry<64;retry++) {
   __asm__ volatile("rdseed %0; setc %1":"=r"(value),"=qm"(ok)::"cc");
   if(ok)break;
   __asm__ volatile("pause");
  }
  if(!ok) {ap_secure_zero(&value,sizeof(value));ap_secure_zero(out,n);return 1;}
  size_t take=n-i<8?n-i:8;
  memcpy(out+i,&value,take);i+=take;
  ap_secure_zero(&value,sizeof(value));
 }
 return 0;
}
