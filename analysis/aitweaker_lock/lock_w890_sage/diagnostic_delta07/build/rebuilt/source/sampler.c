/* Fixed W890 0603 source-SPF observations. No native callbacks or writes. */
#include "sampler.h"
_Static_assert(sizeof(S7_SNAPSHOT)==70,"wire snapshot size");
_Static_assert(sizeof(S7_PAIR)==140,"wire pair size");
#define S7_SPF_BYTES 0xf245cU
static const uint8_t tse_guid[16]={0xdf,0x0a,0xda,0xb1,0x77,0x4f,0x70,0x40,0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a};
static void clear(void *p,size_t n){uint8_t *b=p;while(n--)*b++=0;}
static int same(const void *a,const void *b,size_t n){const uint8_t *p=a,*q=b;while(n--)if(*p++!=*q++)return 0;return 1;}
static int read(const H6_HOST *h,uint64_t base,uint64_t extent,uint32_t off,void *out,size_t n,S7_SNAPSHOT *s){
 uint8_t temporary[8];
 if(!out||!n||n>sizeof(temporary)||base<4096||base>UINT64_MAX-extent||off>extent||n>extent-off){s->status_mask|=S7_INVALID_POINTER;return 0;}
 if(!h->copy(h->context,base+off,temporary,n)){s->status_mask|=S7_UNREADABLE;return 0;}
 for(size_t i=0;i<n;i++)((uint8_t *)out)[i]=temporary[i];
 return 1;
}
static int val(const H6_HOST *h,uint64_t base,uint64_t extent,uint32_t off,void *out,size_t n,unsigned field,S7_SNAPSHOT *s){
 if(!read(h,base,extent,off,out,n,s))return 0;
 s->status_mask|=1U<<field;return 1;
}
static void capture(const H6_HOST *h,uint64_t base,uint64_t bytes,S7_SNAPSHOT *s){
 H6_RESULT code;const H6_PROFILE *profile=h6_profile(tse_guid);
 clear(s,sizeof(*s));
 if(!profile||profile->image_size!=0xde000U||bytes!=0xde000U){s->status_mask=S7_PROFILE_MISMATCH;return;}
 if(!h6_probe(h,base,bytes,profile,&code)){
  s->status_mask=(code.status==H6_RANGE||code.status==H6_RELOC_RANGE)?S7_UNREADABLE:
   (code.status==H6_ALLOC_FAILED||code.status==H6_FREE_FAILED)?S7_PROBE_FAILURE:S7_PROFILE_MISMATCH;
  return;
 }
 s->status_mask|=S7_CODE_MATCH;
 /* All globals are fixed offsets in the exact measured original image. */
 val(h,base,bytes,0xbab20,&s->source,8,0,s);
 val(h,base,bytes,0xbab10,&s->source_pages,8,1,s);
 val(h,base,bytes,0xbab18,&s->source_guids,8,2,s);
 val(h,base,bytes,0xbabc0,&s->current_blob,8,3,s);
 val(h,base,bytes,0xbaaf0,&s->current_pages,8,4,s);
 if(!(s->status_mask&1U))return;
 uint64_t source=s->source;
 if(source<4096||source>UINT64_MAX-S7_SPF_BYTES){s->status_mask|=S7_INVALID_POINTER;return;}
 /* Bootstrap only the mapped fixed header fields. A header size declaration
  * is accepted only after the exact original layout constants agree. */
 uint32_t magic=0,pages=0,controls=0,guids=0;
 if(!val(h,source,0x48,0x44,&s->declared_size,4,5,s)||
    !read(h,source,0x48,0,&magic,4,s)||
    !read(h,source,0x48,0x2c,&pages,4,s)||
    !read(h,source,0x48,0x30,&controls,4,s)||
    !read(h,source,0x48,0x40,&guids,4,s))return;
 if(magic!=0x46505324U||pages!=0x60U||controls!=0x10f78U||guids!=0xf2364U||s->declared_size!=S7_SPF_BYTES){s->status_mask|=S7_PROFILE_MISMATCH;return;}
 s->status_mask|=S7_HEADER_MATCH;
 if((s->status_mask&7U)!=7U)return;
 if(s->source_pages!=source+0x60||s->source_guids!=source+0xf2394){s->status_mask|=S7_PROFILE_MISMATCH;return;}
 s->status_mask|=S7_POINTERS_MATCH;
 uint32_t last=0,guid_count=0,guid_first=0;
 if(!val(h,source,S7_SPF_BYTES,0x60,&s->source_page_count,4,6,s)||
    !val(h,source,S7_SPF_BYTES,0x64,&s->first_page_offset,4,7,s)||
    !read(h,source,S7_SPF_BYTES,0x64+378*4,&last,4,s)||
    !read(h,source,S7_SPF_BYTES,0xf2364,&guid_count,4,s)||
    !read(h,source,S7_SPF_BYTES,0xf2368,&guid_first,4,s))return;
 if(s->source_page_count!=379||s->first_page_offset!=0x650||last!=0x10810||guid_count!=10||guid_first!=0x30){s->status_mask|=S7_PROFILE_MISMATCH;return;}
 s->status_mask|=S7_COUNTS_MATCH;
 /* The alleged offset slot is exactly this original page0 HII field. Read
  * only this declared page field, never follow its low32 as an offset. */
 val(h,source,S7_SPF_BYTES,0x650,&s->source_page0_hii,8,8,s);
 val(h,source,S7_SPF_BYTES,0x12,&s->header_parent_field,2,9,s);
 val(h,source,S7_SPF_BYTES,0x08,&s->header_guid_index,2,10,s);
 val(h,source,S7_SPF_BYTES,0x0a,&s->header_form_id,2,11,s);
 if((s->status_mask&S7_VALID_MASK)==S7_VALID_MASK)s->status_mask|=S7_READS_COMPLETE;
 if(s->status_mask&(1U<<8))s->status_mask|=((uint32_t)s->source_page0_hii?S7_CANDIDATE_NONZERO:S7_CANDIDATE_ZERO);
}
int s7_capture_pair(const H6_HOST *h,uint64_t base,uint64_t bytes,S7_PAIR *out){
 if(!out)return 0;clear(out,sizeof(*out));
 if(!h||!h->copy||!h->alloc||!h->free){out->a.status_mask=out->b.status_mask=S7_PROFILE_MISMATCH;return 0;}
 capture(h,base,bytes,&out->a);capture(h,base,bytes,&out->b);
 if(!same(&out->a,&out->b,sizeof(out->a))){out->a.status_mask|=S7_UNSTABLE;out->b.status_mask|=S7_UNSTABLE;return 0;}
 const uint32_t required=S7_VALID_MASK|S7_CODE_MATCH|S7_HEADER_MATCH|S7_POINTERS_MATCH|S7_COUNTS_MATCH|S7_READS_COMPLETE;
 return (out->a.status_mask&required)==required&&!(out->a.status_mask&(S7_PROFILE_MISMATCH|S7_UNREADABLE|S7_INVALID_POINTER|S7_PROBE_FAILURE));
}
