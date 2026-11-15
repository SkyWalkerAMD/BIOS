/* RFC 1952 single-member gzip with bounded input/output and both trailer checks.
 * Miniz 3.0.2 core inflater is unchanged; no heap, files, ZIP or compression. */
#include "gzip.h"
#define HERO_TINFL_CORE_ONLY
#define MINIZ_NO_STDIO
#define MINIZ_NO_TIME
#define MINIZ_NO_MALLOC
#define MINIZ_NO_DEFLATE_APIS
#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_ZLIB_APIS
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#include "vendor/miniz/miniz_tinfl.c"
static tinfl_decompressor inflater;
uint32_t probe_crc32(const void *,size_t);
ES gzip_decode(const uint8_t *s,UN n,char *out,UN cap,UN *used){
 if(!used)return ERR(2);*used=0;
 if(!s||!out||n<18||n>32768||!cap||cap>32768||s[0]!=31||s[1]!=139||s[2]!=8||(s[3]&0xe0))return ERR(24);
 UN p=10,end=n-8;
 if(s[3]&4){if(end-p<2)return ERR(24);UN extra=u16(s+p);p+=2;if(extra>end-p)return ERR(24);p+=extra;}
 for(unsigned flag=8;flag<=16;flag*=2)if(s[3]&flag){while(p<end&&s[p])p++;if(p==end)return ERR(24);p++;}
 if(s[3]&2){if(end-p<2||(probe_crc32(s,p)&0xffff)!=u16(s+p))return ERR(24);p+=2;}
 if(p>=end||u32(s+n-4)>cap)return ERR(4);
 size_t in=(size_t)(end-p),decoded=(size_t)cap;
 memset(&inflater,0,sizeof(inflater));tinfl_init(&inflater);
 tinfl_status result=tinfl_decompress(&inflater,s+p,&in,(uint8_t *)out,(uint8_t *)out,&decoded,TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
 if(result!=TINFL_STATUS_DONE||in!=end-p||decoded!=u32(s+n-4)||probe_crc32(out,decoded)!=u32(s+n-8))return ERR(24);
 *used=decoded;return 0;
}
