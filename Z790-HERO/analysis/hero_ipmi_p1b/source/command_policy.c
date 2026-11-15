/* P1 has a narrower transport than R2: reads only, no OEM initialization.
 * Selector/length checks precede every KCS register access. */
#include "p1.h"
int p1_read_allowed(uint8_t f,uint8_t c,const uint8_t *p,size_t n){
 if(f==6 && (c==1||c==4||c==0x25||c==0x2f))return n==0;
 if(f==6 && c==0x42)return n==1 && p && p[0]>=1 && p[0]<=11;
 if(f==0xc && c==2)return n==4 && p && p[0]>=1 && p[0]<=11 && !p[2] && !p[3] &&
  (p[1]==3||p[1]==4||p[1]==5||p[1]==6||p[1]==12);
 if(f==0xa && c==0x40)return n==0;
 if(f==0xa && c==0x43)return n==6 && p && !p[0] && !p[1] && !p[4] && p[5]==0xff;
 return 0;
}
