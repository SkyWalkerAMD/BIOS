/* SHA-256 / HMAC-SHA-256 / PBKDF2, implemented from FIPS 180-4 and RFC 8018.
 * No allocation, no libc, no assembly, no external cryptographic dependency.
 * This code is not a FIPS-validated cryptographic module.
 */
#include "password_core.h"

typedef struct { uint32_t h[8]; uint64_t bytes; size_t used; uint8_t block[64]; } SHA;
typedef struct { SHA inner, outer; } HMAC;

static void cp(void *vd, const void *vs, size_t n) {
    uint8_t *d=(uint8_t *)vd; const uint8_t *s=(const uint8_t *)vs;
    while(n--) *d++=*s++;
}
AP_API void ap_secure_zero(void *v, size_t n) {
    volatile uint8_t *p=(volatile uint8_t *)v;
    while(n--) *p++=0;
}
AP_API int ap_constant_equal(const void *av,const void *bv,size_t n) {
    const uint8_t *a=(const uint8_t *)av,*b=(const uint8_t *)bv;
    volatile uint32_t diff=0;
    for(size_t i=0;i<n;i++) diff |= (uint32_t)(a[i]^b[i]);
    return diff==0;
}
static uint32_t rr(uint32_t x,unsigned n) { return (x>>n)|(x<<(32-n)); }
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static void store_be32(uint8_t *p,uint32_t n) {
    p[0]=(uint8_t)(n>>24);p[1]=(uint8_t)(n>>16);p[2]=(uint8_t)(n>>8);p[3]=(uint8_t)n;
}
static void transform(SHA *s,const uint8_t *block) {
    static const uint32_t k[64]={
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64],a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
    for(unsigned i=0;i<16;i++) w[i]=be32(block+4*i);
    for(unsigned i=16;i<64;i++) {
        uint32_t x=w[i-15],y=w[i-2];
        w[i]=(rr(x,7)^rr(x,18)^(x>>3))+w[i-16]+(rr(y,17)^rr(y,19)^(y>>10))+w[i-7];
    }
    for(unsigned i=0;i<64;i++) {
        uint32_t t1=h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^((~e)&g))+k[i]+w[i];
        uint32_t t2=(rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
    ap_secure_zero(w,sizeof(w));
}
static void init(SHA *s) {
    static const uint32_t initial[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    cp(s->h,initial,sizeof(initial));s->bytes=0;s->used=0;ap_secure_zero(s->block,64);
}
static void update(SHA *s,const uint8_t *p,size_t n) {
    s->bytes+=(uint64_t)n;
    while(n) {
        size_t take=64-s->used;if(take>n)take=n;
        cp(s->block+s->used,p,take);s->used+=take;p+=take;n-=take;
        if(s->used==64){transform(s,s->block);s->used=0;}
    }
}
static void finish(SHA *s,uint8_t out[32]) {
    uint64_t bits=s->bytes*8;
    s->block[s->used++]=0x80;
    if(s->used>56){while(s->used<64)s->block[s->used++]=0;transform(s,s->block);s->used=0;}
    while(s->used<56)s->block[s->used++]=0;
    for(unsigned i=0;i<8;i++)s->block[63-i]=(uint8_t)(bits>>(8*i));
    transform(s,s->block);
    for(unsigned i=0;i<8;i++)store_be32(out+4*i,s->h[i]);
    ap_secure_zero(s,sizeof(*s));
}
AP_API void ap_sha256(const uint8_t *p,size_t n,uint8_t out[32]) { SHA s;init(&s);update(&s,p,n);finish(&s,out); }
static void hmac_init(HMAC *h,const uint8_t *key,size_t len) {
    uint8_t pad[64];ap_secure_zero(pad,64);
    if(len>64)ap_sha256(key,len,pad);else cp(pad,key,len);
    for(unsigned i=0;i<64;i++)pad[i]^=0x36;
    init(&h->inner);update(&h->inner,pad,64);
    for(unsigned i=0;i<64;i++)pad[i]^=0x36^0x5c;
    init(&h->outer);update(&h->outer,pad,64);ap_secure_zero(pad,64);
}
static void hmac_run(const HMAC *h,const uint8_t *p,size_t n,uint8_t out[32]) {
    SHA s;uint8_t digest[32];cp(&s,&h->inner,sizeof(s));update(&s,p,n);finish(&s,digest);
    cp(&s,&h->outer,sizeof(s));update(&s,digest,32);finish(&s,out);ap_secure_zero(digest,32);
}
AP_API void ap_hmac_sha256(const uint8_t *key,size_t keylen,const uint8_t *p,size_t n,uint8_t out[32]) {
    HMAC h;hmac_init(&h,key,keylen);hmac_run(&h,p,n,out);ap_secure_zero(&h,sizeof(h));
}
AP_API int ap_pbkdf2_sha256(const uint8_t *pw,size_t pwlen,const uint8_t *salt,size_t saltlen,uint32_t rounds,uint8_t out[32]) {
    HMAC h;uint8_t first[68],u[32],v[32];
    if(!out)return -1;
    if((!pw&&pwlen)||(!salt&&saltlen)||pwlen>AP_PASSWORD_MAX||saltlen>64||rounds==0||rounds>AP_ITERATIONS_MAX){ap_secure_zero(out,32);return -1;}
    hmac_init(&h,pw,pwlen);cp(first,salt,saltlen);
    first[saltlen]=0;first[saltlen+1]=0;first[saltlen+2]=0;first[saltlen+3]=1;
    hmac_run(&h,first,saltlen+4,u);cp(out,u,32);
    for(uint32_t n=1;n<rounds;n++){
        hmac_run(&h,u,32,v);cp(u,v,32);
        for(unsigned i=0;i<32;i++)out[i]^=u[i];
    }
    ap_secure_zero(&h,sizeof(h));ap_secure_zero(first,sizeof(first));ap_secure_zero(u,32);ap_secure_zero(v,32);return 0;
}
