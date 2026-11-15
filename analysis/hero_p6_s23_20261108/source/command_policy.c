/* P1 has a narrower transport than R2: reads only, no OEM initialization.
 * Selector/length checks precede every KCS register access. */
#include "p1.h"
extern unsigned p6_write_armed;
int p1_read_allowed(uint8_t f,uint8_t c,const uint8_t *p,size_t n){
 if(f==6 && (c==1||c==4||c==0x25||c==0x2f))return n==0;
 if(f==6 && c==0x42)return n==1 && p && p[0]>=1 && p[0]<=11;
 if(f==0xc && c==2)return n==4 && p && p[0]>=1 && p[0]<=11 && !p[2] && !p[3] &&
  (p[1]==0||p[1]==3||p[1]==4||p[1]==5||p[1]==6||p[1]==12);
 if(f==0xa && c==0x40)return n==0;
 if(f==0xa && c==0x43)return n==6 && p && (p6_write_armed||(!p[0]&&!p[1])) && !p[4] && p[5]==0xff;
 if(!p6_write_armed)return 0;
 if(f==6 && c==0x22)return n==0;
 if(f==6 && c==0x24)return n==6 && p && (p[0]&7)==3 && !(p[0]&0x38) && !(p[1]&0x88) && (p[1]&7)<=3;
 if(f==6 && c==0x2e)return n==1 && p;
 if(f==0xc && c==1){
  if(!p||n<3||p[0]<1||p[0]>11)return 0;
  if(p[1]==0)return n==3 && p[2]<=2;
  if(p[1]==4)return n==3 && p[2]<=2;
  return n==6 && (p[1]==3||p[1]==6||p[1]==12);
 }
 if(f==0xa && c==0x42)return n==0;
 if(f==0xa && c==0x46)return n==4 && p;
 if(f==0xa && c==0x47)return n==6 && p && p[2]=='C' && p[3]=='L' && p[4]=='R' && (p[5]==0||p[5]==0xaa);
 return 0;
}
