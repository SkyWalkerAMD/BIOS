/* Independent host execution of pure diagnostic storage. No firmware services.
 * Windows threads exercise contention, not the ASUS firmware/AP environment.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "diagnostic_store.h"

static _Alignas(4096) unsigned char arena[8192];
static DIAG09_REGION *region;
static unsigned checks;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %u: %s\n",__LINE__,#x); return 1; } checks++; } while(0)

static void reset(void) {
    memset(arena,0xa5,sizeof(arena));
    region=(void *)(arena+DIAG09_STATE_OFFSET);
    memset(region,0,sizeof(*region));
    region->magic=DIAG09_MAGIC;
    region->revision=DIAG09_REVISION;
    region->bytes=sizeof(*region);
}
static int outside_intact(void) {
    for(size_t i=0;i<sizeof(arena);i++)
        if((i<DIAG09_STATE_OFFSET || i>=DIAG09_STATE_OFFSET+sizeof(*region)) && arena[i]!=0xa5) return 0;
    return 1;
}
static DIAG09_RECORD failure(void) {
    DIAG09_RECORD r={0};
    r.hook=D09_POLL;r.reason=D09_CONTROL_OWNER;r.classification=-1;
    r.valid=D09_V_FRAME|D09_V_CONTROL|D09_V_CONTROL_OWNER;
    r.frame_kind=4;r.control_type=0x0e;r.control_vtable_rva=0x6d6f0;r.control_owner=-1;
    return r;
}
static DWORD WINAPI contend(void *unused) {
    (void)unused;
    for(unsigned i=0;i<5000;i++) {
        DIAG09_RECORD r=failure();
        uint64_t s=d09_request(region,&r);
        if(s) d09_complete(region,s);
        d09_ack(region);
        DIAG09_VIEW v;
        d09_prompt(region,&v);
    }
    return 0;
}
int main(void) {
    DIAG09_RECORD r=failure(),saved;
    DIAG09_VIEW v;
    reset();
    d09_first(region,&r);saved=region->first;
    CHECK(region->first_commit==2 && d09_record_ok(&region->first));
    r.reason=D09_PAGE_MEMORY;d09_first(region,&r);
    CHECK(memcmp(&saved,&region->first,sizeof(saved))==0);
    uint64_t s=d09_request(region,&r);
    CHECK(s==1 && region->request_count==1);
    CHECK(d09_prompt(region,&v) && v.first_valid && v.request_valid && v.ack_count==0);
    saved=region->request;
    CHECK(d09_request(region,&r)==0 && memcmp(&saved,&region->request,sizeof(saved))==0);
    CHECK(d09_prompt(region,&v) && v.first_valid && !v.request_valid && v.ack_count==0);
    d09_ack(region);d09_complete(region,s+1);
    CHECK(d09_prompt(region,&v) && !v.request_valid && v.ack_count==1);
    d09_complete(region,s);
    CHECK(d09_prompt(region,&v) && !v.request_valid && v.first_valid);
    CHECK(d09_request(region,&r)==2 && region->request.request_serial==2);
    CHECK(d09_prompt(region,&v) && !v.request_valid && v.first_valid);
    CHECK(outside_intact());
    reset();d09_first(region,&r);d09_request(region,&r);
    CHECK(d09_prompt(region,&v) && v.request_valid && v.first_valid);
    region->request.crc32^=1;
    CHECK(d09_prompt(region,&v) && !v.request_valid && v.first_valid);
    reset();region->request_commit=1;
    CHECK(d09_request(region,&r)==0 && (region->flags&DIAG09_FLAG_OVERFLOW));
    CHECK(!region->request_count);
    reset();region->request_count=UINT64_MAX;
    CHECK(d09_request(region,&r)==0 && region->request_count==UINT64_MAX);
    reset();region->request_commit=UINT64_MAX-1;
    CHECK(d09_request(region,&r)==0 && region->request_commit==UINT64_MAX-1);
    reset();region->ack_count=region->prompt_count=UINT64_MAX;
    d09_ack(region);CHECK(d09_prompt(region,&v));
    CHECK(v.ack_count==UINT64_MAX && v.prompt_count==UINT64_MAX && (v.flags&DIAG09_FLAG_OVERFLOW));
    reset();region->magic=0;
    unsigned char before[sizeof(arena)];memcpy(before,arena,sizeof(arena));
    d09_first(region,&r);d09_request(region,&r);d09_ack(region);d09_complete(region,1);
    CHECK(!d09_prompt(region,&v) && !v.request_valid && !v.first_valid);
    CHECK(memcmp(before,arena,sizeof(arena))==0);
    reset();region->flags=0x80000000;memcpy(before,arena,sizeof(arena));
    CHECK(!d09_request(region,&r) && !d09_prompt(region,&v));
    CHECK(memcmp(before,arena,sizeof(arena))==0);
    reset();region->writer_lock=1;
    CHECK(!d09_request(region,&r) && !d09_prompt(region,&v));
    CHECK(region->writer_lock==1 && (region->flags&DIAG09_FLAG_DROPPED_WRITER));
    CHECK(outside_intact());
    reset();
    HANDLE threads[4];
    for(unsigned i=0;i<4;i++) { threads[i]=CreateThread(NULL,0,contend,NULL,0,NULL);CHECK(threads[i]!=NULL); }
    CHECK(WaitForMultipleObjects(4,threads,TRUE,30000)==WAIT_OBJECT_0);
    for(unsigned i=0;i<4;i++) CloseHandle(threads[i]);
    CHECK(region->writer_lock==0 && region->request_count<=20000 && region->prompt_count<=20000 && region->ack_count<=20000);
    CHECK(d09_header(region) && d09_prompt(region,&v));
    CHECK(!v.request_valid || d09_record_ok(&v.request));
    CHECK(outside_intact());
    printf("{\"status\":\"PASS_PURE_STORAGE_HOST_BOUNDARIES\",\"checks\":%u,\"threads\":4,\"iterations_per_thread\":5000,\"request_count\":%llu,\"prompt_count\":%llu,\"ack_count\":%llu,\"device_calls\":0}\n",checks,(unsigned long long)region->request_count,(unsigned long long)region->prompt_count,(unsigned long long)region->ack_count);
    return 0;
}
