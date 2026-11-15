/* TLS 1.2 plaintext handshake parser for an explicitly provisioned leaf pin.
 * No application bytes are sent before both exact pin match and successful
 * native cryptographic handshake. TLS still verifies key exchange and Finished.
 * This private policy does not rely on the expired factory PKI dates.
 * No resumption/session ID is configured. ServerHello must select the explicit
 * TLS 1.2 RSA-authenticated AES GCM / SHA256-CBC allowlist below.
 */
#include "peer_certificate.h"
typedef struct {uint8_t header[4],message[16384];UN header_used,used,wanted;int seen,encrypted,hello_seen;uint16_t cipher;} PIN_STATE;
static PIN_STATE pin;
static UN be24(const uint8_t *p){return (UN)p[0]*65536+(UN)p[1]*256+p[2];}
static ES pin_certificate(const uint8_t *p,UN n){
 if(pin.seen||n<6||be24(p)!=n-3)return ERR(26);
 UN first=be24(p+3);if(first!=sizeof(pinned_leaf)||first>n-6||!eq(p+6,pinned_leaf,first))return ERR(26);
 UN off=3;unsigned count=0;
 while(off<n){if(n-off<3||++count>16)return ERR(24);UN size=be24(p+off);off+=3;if(!size||size>n-off)return ERR(24);off+=size;}
 pin.seen=1;logtext("PTLS_EXACT_LEAF_PIN_MATCH\r\n");return 0;
}
static ES pin_record(const uint8_t *r,UN n){
 if(n<5)return ERR(24);
 if(r[0]==20){if(!pin.seen||pin.header_used||pin.used||n!=6||r[5]!=1)return ERR(26);pin.encrypted=1;return 0;}
 if(r[0]!=22||pin.encrypted)return 0;
 UN off=5;
 while(off<n){
  while(pin.header_used<4&&off<n)pin.header[pin.header_used++]=r[off++];
  if(pin.header_used<4)break;
  pin.wanted=be24(pin.header+1);if(pin.wanted>sizeof(pin.message))return ERR(4);
  UN add=pin.wanted-pin.used;if(add>n-off)add=n-off;
  memcpy(pin.message+pin.used,r+off,add);pin.used+=add;off+=add;
  if(pin.used< pin.wanted)break;
  if(pin.header[0]==11){ES e=pin_certificate(pin.message,pin.wanted);if(FAILED(e))return e;}
  else if(pin.header[0]==2){
   if(pin.hello_seen||pin.wanted<38||pin.message[0]!=3||pin.message[1]!=3||pin.message[34]>32)return ERR(26);
   UN offset=35+pin.message[34];if(offset+3>pin.wanted||pin.message[offset+2]!=0)return ERR(26);
   pin.cipher=(uint16_t)((unsigned)pin.message[offset]*256+pin.message[offset+1]);
   if(pin.cipher!=0xc02f&&pin.cipher!=0xc030&&pin.cipher!=0x009c&&pin.cipher!=0x009d&&pin.cipher!=0x003c&&pin.cipher!=0x003d)return ERR(26);
   pin.hello_seen=1;status("PTLS_NEGOTIATED_CIPHER",pin.cipher);
  }
  pin.header_used=pin.used=pin.wanted=0;
 }
 return 0;
}
