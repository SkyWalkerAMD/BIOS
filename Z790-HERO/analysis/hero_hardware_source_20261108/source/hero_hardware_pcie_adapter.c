#include "hhs_common.h"
#include "hero_hardware_pcie_adapter.h"
static int overlap(const void *a,size_t an,const void *b,size_t bn){uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
 if(an>UINTPTR_MAX-x||bn>UINTPTR_MAX-y)return 1;return x<y+bn&&y<x+an;}
int HeroHardwarePciSinkInit(HHS_PCI_SINK *sink,HPC_PCI_RECORD *records,uint32_t capacity){
 if(!sink||!records||!capacity||capacity>HPC_PCI_MAX||overlap(sink,sizeof(*sink),records,(size_t)capacity*sizeof(*records)))return 1;
 sink->records=records;sink->capacity=capacity;sink->used=0;sink->rejected=0;sink->reserved=0;return 0;
}
int HeroHardwarePciVisit(void *user,const HHS_RECORD *r){
 HHS_PCI_SINK *s=user;if(!s||!r||s->reserved||s->rejected||!s->records||!s->capacity||s->capacity>HPC_PCI_MAX)return 1;
 if(r->version!=HHS_VERSION||r->bytes!=sizeof(*r)){s->rejected=1;return 1;}
 if(r->kind!=HHS_PCI)return 0;
 const HHS_PCI_VIEW *v=&r->data.pci;const HHS_PATH_VIEW *p=&r->path;
 if(s->used>=s->capacity||r->source_index!=s->used||!r->protocol_readable||!r->valid||r->incomplete||r->issues||r->protocol_status||
    v->flags!=HHS_PCI_VALID||v->location_status||v->config_status||v->segment>65535||v->bus>255||v->device>31||v->function>7||
    !v->config||v->config_bytes!=256||v->config_crc32!=probe_crc32(v->config,256)||
    !p->valid||!p->stable||p->protocol_status||p->first_status||p->second_status||!p->first||!p->second||!p->first_bytes||
    p->first_bytes>HPC_PATH_MAX||p->first_bytes!=p->second_bytes||!eq(p->first,p->second,p->first_bytes)||
    p->first_crc32!=probe_crc32(p->first,p->first_bytes)||p->second_crc32!=p->first_crc32){s->rejected=1;return 1;}
 HPC_PCI_RECORD *dst=&s->records[s->used];
 if(overlap(dst,sizeof(*dst),r,sizeof(*r))||overlap(dst,sizeof(*dst),v->config,256)||overlap(dst,sizeof(*dst),p->first,p->first_bytes)||overlap(dst,sizeof(*dst),p->second,p->second_bytes)){
  s->rejected=1;return 1;
 }
 memset(dst,0,sizeof(*dst));dst->source_index=r->source_index;dst->flags=HPC_CAPTURE_VALID;dst->config_crc32=v->config_crc32;dst->path_crc32=p->first_crc32;dst->path_bytes=p->first_bytes;
 dst->source_handle=r->source_handle;dst->segment=(uint16_t)v->segment;dst->bus=(uint8_t)v->bus;dst->device=(uint8_t)v->device;dst->function=(uint8_t)v->function;
 memcpy(dst->config,v->config,256);memcpy(dst->path,p->first,p->first_bytes);s->used++;return 0;
}
int HeroHardwarePciCapture(const HHS_PCI_SINK *s,const HHS_RESULT *r,HPC_CAPTURE *out){
 if(!s||!r||!out||s->rejected||s->reserved||!s->records||!s->capacity||s->capacity>HPC_PCI_MAX||s->used>s->capacity||
    r->version!=HHS_VERSION||r->bytes!=sizeof(*r)||overlap(out,sizeof(*out),s,sizeof(*s))||overlap(out,sizeof(*out),r,sizeof(*r))||
    overlap(out,sizeof(*out),s->records,(size_t)s->capacity*sizeof(*s->records)))return 1;
 const HHS_GROUP *g=&r->groups[0];
 if(g->kind!=HHS_PCI||g->limit!=HHS_PCI_LIMIT||g->declared>HPC_PCI_MAX||g->captured!=g->declared||g->captured!=s->used||
    g->valid_records!=g->captured||!g->complete||!g->stable||g->truncated||g->incomplete_records||g->cleanup_status||g->issues||
    g->reserved||g->reserved_map||g->reserved2||g->source_bytes>UINT32_MAX||
    !(g->enum_status==0||(g->enum_status==ERR(14)&&g->declared==0)))return 1;
 HPC_CAPTURE capture;memset(&capture,0,sizeof(capture));capture.version=1;capture.pci_declared=(uint32_t)g->declared;
 capture.pci_captured=g->captured;capture.pci_complete=1;capture.pci_status=g->enum_status;capture.source_crc32=g->source_crc32;capture.source_bytes=(uint32_t)g->source_bytes;*out=capture;return 0;
}
