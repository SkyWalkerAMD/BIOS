/* Host-only wrapper for pinned EDK II's public-domain LZMA SDK. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "LzmaEnc.h"
#include "LzmaDec.h"
static void *a(ISzAllocPtr p,size_t n){(void)p;return malloc(n);}
static void f(ISzAllocPtr p,void *v){(void)p;free(v);}
static const ISzAlloc allocator={a,f};
int main(int argc,char **argv){
 if(argc!=3)return 2;
 FILE *in=fopen(argv[1],"rb");if(!in)return 3;
 if(fseek(in,0,SEEK_END))return 4;long length=ftell(in);if(length<=0||length>64*1024*1024)return 5;
 rewind(in);size_t n=(size_t)length,cap=n+n/20+65536;
 unsigned char *plain=malloc(n),*out=malloc(cap+13),*verify=malloc(n);if(!plain||!out||!verify)return 6;
 if(fread(plain,1,n,in)!=n)return 7;fclose(in);
 CLzmaEncProps props;LzmaEncProps_Init(&props);props.dictSize=0x1000000;props.numThreads=1;
 size_t encoded=cap,prop_size=5;
 int rc=LzmaEncode(out+13,&encoded,plain,n,&props,out,&prop_size,0,NULL,&allocator,&allocator);
 if(rc||prop_size!=5)return 8;
 for(int i=0;i<8;i++)out[5+i]=(unsigned char)((unsigned long long)n>>(8*i));
 size_t decoded=n,consumed=encoded;ELzmaStatus status;
 rc=LzmaDecode(verify,&decoded,out+13,&consumed,out,5,LZMA_FINISH_END,&status,&allocator);
 if(rc||decoded!=n||consumed!=encoded||memcmp(plain,verify,n))return 9;
 FILE *dest=fopen(argv[2],"wb");if(!dest)return 10;
 if(fwrite(out,1,encoded+13,dest)!=encoded+13||fclose(dest))return 11;
 free(plain);free(out);free(verify);return 0;
}
