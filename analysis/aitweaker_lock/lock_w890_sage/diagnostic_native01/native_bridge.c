/* Additional read-only sampling after exact .text digest checks. */
#include "efi_min.h"
#include "native_sample.h"
#include "password_core.h"
static uint8_t memory_map[65536];
static UN map_bytes,map_stride;static uint32_t map_version;
static void (*output)(const char *);
static void field(const char *key,uint64_t value){
 char text[17];static const char digits[]="0123456789ABCDEF";
 for(unsigned i=0;i<16;i++)text[i]=digits[(value>>(60-4*i))&15];text[16]=0;
 output(key);output("=0x");output(text);output("\r\n");
}
static int same(const uint8_t *a,const uint8_t *b,size_t n){while(n--)if(*a++!=*b++)return 0;return 1;}
static int copy(void *context,uint64_t address,void *destination,size_t bytes){
 (void)context;if(!ns_range(memory_map,(size_t)map_bytes,(size_t)map_stride,map_version,address,bytes))return 0;
 const volatile uint8_t *p=(const volatile uint8_t *)(uintptr_t)address;uint8_t *q=destination;
 for(size_t i=0;i<bytes;i++)q[i]=p[i];return 1;
}
int native_read_only(ST *st,void *tse,void *setup,void (*emit)(const char *)){
 static const uint8_t tse_digest[32]={0xe0,0xb8,0x09,0x4c,0x48,0x2a,0x64,0x7d,0x71,0x96,0xd1,0x3a,0xa3,0xb0,0x59,0x90,0xd4,0x85,0x6d,0xc3,0x5d,0xe8,0xae,0xe1,0x03,0xb9,0xf9,0x35,0xfe,0x35,0xd9,0x58};
 static const uint8_t setup_digest[32]={0x49,0xad,0x95,0xff,0x56,0x45,0x19,0xfd,0xdf,0x96,0x62,0x71,0xe9,0x78,0x01,0x6a,0x5b,0xc5,0x18,0xa4,0x88,0xb3,0xb6,0x12,0xbd,0xc7,0x93,0xa0,0xc7,0x35,0xb1,0xd0};
 output=emit;output("W890_NATIVE_SAMPLE01_BEGIN\r\n");
 output("NATIVE_SAMPLE_IS_NOT_AN_AUTHORIZATION_OR_OWNERSHIP_PROOF\r\n");
 if(!tse||!setup||!st||!st->bs||!st->bs->get_memory_map){output("NATIVE_SAMPLE_STATUS=UNAVAILABLE\r\n");return 0;}
 typedef ES(EA *GET_MAP)(UN *,void *,UN *,UN *,uint32_t *);
 map_bytes=sizeof(memory_map);map_stride=0;map_version=0;UN map_key=0;
 ES status=((GET_MAP)st->bs->get_memory_map)(&map_bytes,memory_map,&map_key,&map_stride,&map_version);
 field("Native.GetMemoryMap",status);
 if(FAILED(status)||map_bytes>sizeof(memory_map)){output("NATIVE_SAMPLE_STATUS=MEMORY_MAP_UNAVAILABLE\r\n");return 0;}
 uint64_t tse_address=(uint64_t)(uintptr_t)tse,setup_address=(uint64_t)(uintptr_t)setup;
 if(tse_address>UINT64_MAX-4096||setup_address>UINT64_MAX-4096||
    !ns_range(memory_map,(size_t)map_bytes,(size_t)map_stride,map_version,tse_address+4096,597466)||
    !ns_range(memory_map,(size_t)map_bytes,(size_t)map_stride,map_version,setup_address+4096,174073)){
  output("NATIVE_SAMPLE_STATUS=TEXT_RANGE_REFUSED\r\n");return 0;
 }
 uint8_t digest[32];ap_sha256((const uint8_t *)tse+4096,597466,digest);
 if(!same(digest,tse_digest,32)){output("NATIVE_SAMPLE_STATUS=AMITSE_TEXT_MISMATCH\r\n");return 0;}
 ap_sha256((const uint8_t *)setup+4096,174073,digest);
 if(!same(digest,setup_digest,32)){output("NATIVE_SAMPLE_STATUS=SETUP_TEXT_MISMATCH\r\n");return 0;}
 NS_SAMPLE sample;int result=ns_sample(copy,0,(uint64_t)(uintptr_t)tse,909312,&sample);
 field("Native.sample_result",(uint64_t)result);field("Native.memory_map_bytes",map_bytes);field("Native.memory_map_stride",map_stride);
 if(result!=NS_OK&&result!=NS_INACTIVE){output("NATIVE_SAMPLE_STATUS=REFUSED\r\n");return 0;}
 field("Native.AMITSE",(uint64_t)(uintptr_t)tse);field("Native.Setup",(uint64_t)(uintptr_t)setup);
 field("Native.app",sample.globals.app);field("Native.stage",sample.globals.stage);field("Native.boot_services",sample.globals.boot_services);
 field("Native.string_hii",sample.globals.string_hii);field("Native.history",sample.globals.history);
 field("Native.history_root",sample.globals.history_root);field("Native.history_capacity",sample.globals.history_capacity);field("Native.history_count",sample.globals.history_count);
 if(result==NS_INACTIVE){output("NATIVE_SAMPLE_STATUS=INACTIVE\r\n");return 0;}
 field("Native.current_index",sample.current_index);field("Native.page_count",sample.page_count);field("Native.page_array",sample.page_array);
 field("Native.page",sample.page);field("Native.page_hii",sample.hii);field("Native.form",sample.form);field("Native.page_index",sample.index);field("Native.parent",sample.parent);
 field("Native.redraw",sample.redraw);field("Native.exit",sample.exit_flag);field("Native.menu_mode",sample.menu_mode);field("Native.page_flags",sample.page_flags);
 field("Native.frames",sample.frames);field("Native.frame_count",sample.frame_count);field("Native.extras",sample.extras);field("Native.extra_count",sample.extra_count);
 output("NATIVE_SAMPLE_STATUS=STABLE_DOUBLE_SAMPLE\r\n");
 output("W890_NATIVE_SAMPLE01_END\r\n");
 return 1;
}
