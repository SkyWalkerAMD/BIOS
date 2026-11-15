/* P3 KVM: same P2 inventory, display-only export; not a password lock. */
#include "efi_min.h"
#include "probe_core.h"
#include "profiles.h"
#include "kvm.h"
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID hii_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID browser_guid={0xb9d4c360,0xbcfb,0x4f9b,{0x92,0x98,0x53,0xc1,0x36,0x98,0x22,0x58}};
static GUID config_guid={0x330d4706,0xf2a0,0x4e4f,{0xa3,0x69,0xb6,0x6f,0xa8,0xd5,0x43,0x85}};
static GUID post_guid={0x8a91b1e1,0x56c7,0x4adc,{0xab,0xeb,0x1c,0x2c,0xa1,0x72,0x9e,0xff}};
static GUID tse_guid={0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}};
static GUID setup_guid={0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}};
static ST *st;
static HANDLE *images;
static UN image_count;
static char logbuf[65536];
static size_t loglen;
static int truncated;
static unsigned warnings,known_modules,hii_valid;
void *memset(void *p,int c,size_t n) { uint8_t *a=p;while(n--)*a++=(uint8_t)c;return p; }
void *memcpy(void *p,const void *q,size_t n) { uint8_t *a=p;const uint8_t *b=q;while(n--)*a++=*b++;return p; }
static int equal(const void *p,const void *q,size_t n) {
    const uint8_t *a=p,*b=q;while(n--)if(*a++!=*b++)return 0;return 1;
}
static void screen(const char *s) {
    C16 w[160];size_t n=0;
    if (!st->out || !st->out->out)return;
    while(*s) {
        w[n++]=(uint8_t)*s++;
        if(n==159 || !*s) { w[n]=0;st->out->out(st->out,w);n=0; }
    }
}
static void emit(const char *s) {
    while(*s) { if(loglen<sizeof(logbuf))logbuf[loglen++]=*s;else truncated=1;s++; }
}
static void hex(uint64_t n,unsigned digits) {
    static const char h[]="0123456789ABCDEF";char b[17];
    if(digits>16)digits=16;
    for(unsigned i=0;i<digits;i++)b[i]=h[(n>>((digits-i-1)*4))&15];
    b[digits]=0;emit(b);
}
static void number(uint64_t n) {
    char b[24];unsigned k=23;b[k]=0;
    do { b[--k]=(char)('0'+n%10);n/=10; }while(n);
    emit(b+k);
}
static void status(const char *s,ES e) { emit(s);emit("=0x");hex(e,16);emit("\r\n"); }
static void warning(const char *s,ES e) { warnings++;status(s,e); }
static void release(void *p) {
    ES e=st->bs->free_pool(p);
    if(FAILED(e))warning("FreePool",e);
}
static void guid_text(const GUID *g) {
    hex(g->a,8);emit("-");hex(g->b,4);emit("-");hex(g->c,4);emit("-");
    for(unsigned k=0;k<8;k++) { if(k==2)emit("-");hex(g->d[k],2); }
}
static int fv_guid(LOADED *li,GUID *g) {
    const uint8_t *p=li->filepath;
    if(!p)return 0;
    for(size_t pos=0;pos+4<=1024;) {
        uint16_t n=(uint16_t)(p[pos+2]|((uint16_t)p[pos+3]<<8));
        if(n<4 || n>1024-pos || p[pos]==0x7f)return 0;
        if(p[pos]==4 && p[pos+1]==6 && n==20) { memcpy(g,p+pos+4,16);return 1; }
        pos+=n;
    }
    return 0;
}
static LOADED *loaded(HANDLE h) {
    LOADED *li=0;
    if(FAILED(st->bs->handle_protocol(h,&loaded_guid,(void **)&li)))return 0;
    return li;
}
static void owner(const char *label,void *fn) {
    emit(label);emit(" ");
    if(!fn) { emit("NULL\r\n");warnings++;return; }
    for(UN k=0;k<image_count;k++) {
        LOADED *li=loaded(images[k]);
        if(!li || !li->image_base)continue;
        UN addr=(UN)fn,base=(UN)li->image_base;
        if(addr<base || addr-base>=li->image_size)continue;
        GUID g;
        if(fv_guid(li,&g))guid_text(&g);else emit("NON_FV_IMAGE");
        emit(" RVA=0x");hex(addr-base,8);emit("\r\n");return;
    }
    emit("OWNER_NOT_RESOLVED\r\n");warnings++;
}
static void inspect_images(void) {
    ES e=st->bs->locate_handles(2,&loaded_guid,0,&image_count,&images);
    status("LoadedImage.enumerate",e);
    if(FAILED(e)||!images||!image_count||image_count>4096) {
        warnings++;
        /* Output parameters from a failed service are not trusted. */
        if(!FAILED(e)&&images)release(images);
        images=0;image_count=0;return;
    }
    emit("LoadedImage.count=");number(image_count);emit("\r\n");
    unsigned matched=0;
    for(UN k=0;k<image_count && !truncated;k++) {
        LOADED *li=loaded(images[k]);GUID g;
        if(!li || !fv_guid(li,&g))continue;
        if(!equal(&g,&tse_guid,16)&&!equal(&g,&setup_guid,16))continue;
        matched++;
        emit(equal(&g,&tse_guid,16)?"AMITSE ":"Setup ");
        IMAGE_INFO info;
        if(!probe_image(li->image_base,(size_t)li->image_size,&info)) {
            emit("IMAGE_PARSE_FAILED\r\n");warnings++;continue;
        }
        emit("text_crc32=0x");hex(info.text_crc,8);
        emit(" text_rva=0x");hex(info.text_rva,8);
        emit(" text_size=0x");hex(info.text_size,8);
        emit(" entry=0x");hex(info.entry,8);emit("\r\n");
        const char *name="UNKNOWN_BUILD";
        for(unsigned i=0;i<sizeof(profiles)/sizeof(profiles[0]);i++) {
            const PROFILE *p=&profiles[i];
            if(equal(&g,&p->guid,16)&&info.text_crc==p->crc&&info.text_rva==p->rva&&
               info.text_size==p->size&&info.entry==p->entry&&info.image_size==p->image_size) {
                name=p->name;known_modules|=equal(&g,&tse_guid,16)?1U:2U;break;
            }
        }
        emit("Build fingerprint: ");emit(name);emit("\r\n");
        if(equal(name,"UNKNOWN_BUILD",13))warnings++;
    }
    emit("Target modules found=");number(matched);emit("\r\n");
    if(known_modules!=3)warnings++;
}
static void inspect_protocols(void) {
    BROWSER *browser=0;void *post=0;
    ES e=st->bs->locate_protocol(&browser_guid,0,(void **)&browser);
    status("FormBrowser2.locate",e);
    if(!FAILED(e)&&browser) {
        owner("FormBrowser2.SendForm",browser->send_form);
        owner("FormBrowser2.BrowserCallback",browser->browser_callback);
    } else warnings++;
    e=st->bs->locate_protocol(&post_guid,0,&post);
    status("AMI.PostManager.locate",e);
    emit("AMI.PostManager.interface=");emit(!FAILED(e)&&post?"PRESENT\r\n":"ABSENT\r\n");
    if(FAILED(e)||!post)warnings++;
    /* The private AMI protocol is intentionally not dereferenced or called. */
}
static void inspect_hii(void) {
    HII *hii=0;HANDLE *handles=0;UN bytes=0;
    ES e=st->bs->locate_protocol(&hii_guid,0,(void **)&hii);
    status("HiiDatabase.locate",e);
    if(FAILED(e)||!hii) { warnings++;return; }
    if(!hii->list||!hii->export_list||!hii->get_driver) {
        warning("HiiDatabase.missing_method",ERR(3));return;
    }
    e=hii->list(hii,2,0,&bytes,0);
    if(e!=ERR(5)||!bytes||bytes>32768||bytes%sizeof(HANDLE)) { warning("HiiDatabase.list_size",e);return; }
    UN capacity=bytes;
    e=st->bs->allocate_pool(4,capacity,(void **)&handles);
    if(FAILED(e)||!handles) { warning("HiiDatabase.allocate",e);return; }
    e=hii->list(hii,2,0,&bytes,handles);
    if(FAILED(e)||!bytes||bytes>capacity||bytes%sizeof(HANDLE)) { warning("HiiDatabase.list",e);release(handles);return; }
    emit("HII form-package handles=");number(bytes/sizeof(HANDLE));emit("\r\n");
    for(UN i=0;i<bytes/sizeof(HANDLE) && !truncated;i++) {
        UN size=0;uint8_t *buffer=0;
        e=hii->export_list(hii,handles[i],&size,0);
        if((e!=ERR(5)&&e!=ERR(9))||size<20||size>16*1024*1024) { warning("HII export_size",e);continue; }
        UN cap=size;
        e=st->bs->allocate_pool(4,cap,(void **)&buffer);
        if(FAILED(e)||!buffer) { warning("HII allocate",e);continue; }
        e=hii->export_list(hii,handles[i],&size,buffer);
        if(FAILED(e)||size>cap) { warning("HII export",e);release(buffer);continue; }
        HII_INFO info;
        if(!probe_hii(buffer,(size_t)size,&info)) {
            emit("HII package parse failed\r\n");warnings++;release(buffer);continue;
        }
        hii_valid++;
        /* Log only structural counts and module ownership; no HII strings,
         * question values, password buffers, or package contents are saved. */
        emit("HII ");guid_text((GUID *)buffer);
        emit(" forms=");number(info.forms);emit(" password_controls=");number(info.password_questions);
        emit(" main_form_2713=");number(info.form_2713);emit(" main_form_2714=");number(info.form_2714);emit("\r\n");
        HANDLE driver=0;
        e=hii->get_driver(hii,handles[i],&driver);
        if(!FAILED(e)&&driver) {
            CONFIG *config=0;
            e=st->bs->handle_protocol(driver,&config_guid,(void **)&config);
            if(!FAILED(e)&&config) {
                owner("  ConfigAccess.ExtractConfig",config->extract);
                owner("  ConfigAccess.RouteConfig",config->route);
                owner("  ConfigAccess.Callback",config->callback);
            } else warning("  ConfigAccess.locate",e);
        } else warning("  HII.driver",e);
        release(buffer);
    }
    release(handles);
}

int memory_present(const void *p,UN n,int write) {
 uint64_t a=(uint64_t)(uintptr_t)p,end,cr3,cr4;
 if(!n || a<4096 || a>0x0000ffffffffffffULL || n>0x0001000000000000ULL-a)return 0;
 end=a+n-1;
 __asm__ volatile("mov %%cr3,%0":"=r"(cr3));__asm__ volatile("mov %%cr4,%0":"=r"(cr4));
 for(a&=~4095ULL;a<=end;a+=4096) {
  uint64_t table=cr3&0x000ffffffffff000ULL;int levels=(cr4&(1ULL<<12))?5:4;
  for(int level=levels;level>=1;level--) {
   uint64_t entry=((volatile uint64_t *)(uintptr_t)table)[(a>>(12+9*(level-1)))&511];
   if(!(entry&1) || (write && !(entry&2)))return 0;
   if(level==1 || ((level==2 || level==3) && (entry&128)))break;
   table=entry&0x000ffffffffff000ULL;if(!table)return 0;
  }
 }
 return 1;
}

static GUID smbios3_guid={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
static GUID smbios_guid={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0,0x90,0x27,0x3f,0xc1,0x4d}};
#define system_table st
#define memcmp(a,b,n) (!equal((a),(b),(n)))
static int equal_ascii(const uint8_t *s,UN size,const char *want) {
 UN i=0;for(;i<size && want[i];i++)if(s[i]!=(uint8_t)want[i])return 0;
 return i<size && !want[i] && !s[i];
}
static int smbios_string(const uint8_t *s,UN n,uint8_t index,const char *wanted) {
 if(!index)return 0;
 UN p=s[1];for(unsigned i=1;i<index;i++) {while(p<n && s[p])p++;if(p+1>=n || !s[p+1])return 0;p++;}
 return p<n && equal_ascii(s+p,n-p,wanted);
}
static int smbios_table(uint8_t *data,UN size) {
 if(size<6 || size>2*1024*1024 || !memory_present(data,size,0))return 0;
 int board=0,version=0;
 for(UN p=0,count=0;p+6<=size && count<4096;count++) {
  uint8_t type=data[p],length=data[p+1];if(length<4 || length>size-p)return 0;
  UN end=p+length;while(end+1<size && (data[end] || data[end+1]))end++;
  if(end+1>=size)return 0;end+=2;
  if(type==0 && length>=6)version=smbios_string(data+p,end-p,data[p+5],"1904");
  if(type==2 && length>=6)board=smbios_string(data+p,end-p,data[p+5],"Pro WS W790-ACE");
  if(type==127)break;p=end;
 }
 return board && version;
}
static int board_matches(void) {
 for(UN i=0;i<system_table->table_count;i++) {
  CT *ct=&system_table->tables[i];uint8_t *p=ct->table;UN length=0,size=0;uint64_t address=0;
  if(!memcmp(&ct->guid,&smbios3_guid,16)) {
   if(!memory_present(p,24,0) || memcmp(p,"_SM3_",5))continue;
   length=p[6];if(length<24 || length>64 || !memory_present(p,length,0))continue;
   uint32_t n;memcpy(&n,p+12,4);size=n;memcpy(&address,p+16,8);
  } else if(!memcmp(&ct->guid,&smbios_guid,16)) {
   if(!memory_present(p,31,0) || memcmp(p,"_SM_",4))continue;
   length=p[5];if(length<31 || length>64 || !memory_present(p,length,0))continue;
   uint16_t n;uint32_t a;memcpy(&n,p+22,2);memcpy(&a,p+24,4);size=n;address=a;
  } else continue;
  uint8_t sum=0;for(UN j=0;j<length;j++)sum=(uint8_t)(sum+p[j]);
  if(!sum && smbios_table((uint8_t *)(uintptr_t)address,size))return 1;
 }
 return 0;
}

#undef memcmp
#undef system_table
/* Included after the original P3 helpers. All added operations are read-only.
 * No SetVariable, hook installation, HII update, SPI or filesystem writes. */
typedef struct P4RNG P4RNG;
struct P4RNG {void *info;ES(EA *get)(P4RNG *,GUID *,UN,uint8_t *);};
typedef struct P4CPU P4CPU;
struct P4CPU {void *flush,*enable,*disable,*state,*init,*interrupt;
 ES(EA *timer)(P4CPU *,uint32_t,uint64_t *,uint64_t *);void *attributes;uint32_t count,alignment;};
typedef struct P4ATTR P4ATTR;
struct P4ATTR {ES(EA *get)(P4ATTR *,uint64_t,uint64_t,uint64_t *);void *set,*clear;};
typedef ES(EA *P4GETVAR)(C16 *,GUID *,uint32_t *,UN *,void *);
static GUID rng_guid={0x3152bca5,0xeade,0x433d,{0x86,0x2e,0xc0,0x1c,0xdc,0x29,0x1f,0x44}};
static GUID cpu_guid={0x26baccb1,0x6f42,0x11d4,{0xbc,0xe7,0,0x80,0xc7,0x3c,0x88,0x81}};
static GUID attr_guid={0xf4560cf6,0x40ec,0x4b4a,{0xa1,0x92,0xbf,0x1d,0x57,0xd0,0xb1,0x89}};
static GUID global_guid={0x8be4df61,0x93ca,0x11d2,{0xaa,0x0d,0,0xe0,0x98,0x03,0x2b,0x8c}};
static GUID credential_guid={0x750e9d9d,0xf2d8,0x4e14,{0x9b,0x53,0x89,0x23,0xa7,0x19,0x04,0x61}};
static GUID oc_guid={0xa3a3b874,0x7636,0x4182,{0xba,0x1e,0xf5,0x2c,0x58,0x44,0x94,0xe3}};
static GUID memory_guid={0x98cf19ed,0x4109,0x4681,{0xb7,0x9d,0x91,0x96,0x75,0x7c,0x78,0x24}};
static void field(const char *name,uint64_t value) {emit(name);emit("=0x");hex(value,16);emit("\r\n");}
static void variable_info(P4GETVAR get,const char *label,C16 *name,GUID *guid) {
 UN size=0;uint32_t attributes=0;ES e=get(name,guid,&attributes,&size,0);
 status(label,e);emit("  bytes=");number(size);emit(" attributes=0x");hex(attributes,8);emit("\r\n");
}
static void inspect_preflight(void) {
 emit("P4_PREFLIGHT_BEGIN\r\nVariant=W790_ACE_1904_READONLY\r\n");
 field("Production.SMBIOS.board_match",board_matches());
 uint64_t cr0;__asm__ volatile("mov %%cr0,%0":"=r"(cr0));field("CPU.CR0.WP",(cr0>>16)&1);
 P4RNG *rng=0;ES e=st->bs->locate_protocol(&rng_guid,0,(void **)&rng);status("RNG.locate",e);
 if(!FAILED(e)&&rng&&rng->get) {uint8_t sample[32];e=rng->get(rng,0,sizeof(sample),sample);status("RNG.get32",e);volatile uint8_t *v=sample;for(unsigned i=0;i<32;i++)v[i]=0;}
 P4CPU *cpu=0;e=st->bs->locate_protocol(&cpu_guid,0,(void **)&cpu);status("CpuArch.locate",e);
 if(!FAILED(e)&&cpu&&cpu->timer) {
  field("CpuArch.timers",cpu->count);uint64_t a=0,b=0,period=0;
  e=cpu->timer(cpu,0,&a,&period);status("CpuArch.timer0",e);field("CpuArch.period_fs",period);
  if(!FAILED(e)) {st->bs->stall(100000);e=cpu->timer(cpu,0,&b,0);status("CpuArch.timer0_after",e);field("CpuArch.monotonic",b>a);field("CpuArch.delta_100ms",b-a);}
 }
 P4ATTR *attr=0;e=st->bs->locate_protocol(&attr_guid,0,(void **)&attr);status("MemoryAttribute.locate",e);
 if(FAILED(e))attr=0;
 uint8_t *tse=0;UN tse_size=0;
 for(UN i=0;i<image_count;i++) {LOADED *li=loaded(images[i]);GUID g;if(li&&fv_guid(li,&g)&&equal(&g,&tse_guid,16)){tse=li->image_base;tse_size=li->image_size;}}
 if(tse && tse_size>0x92b10) {
  const uint32_t locations[]={0xe208,0x15370,0x6af78,0x6af80,0x6ae90,0x7cb30,0x82998};
  for(unsigned i=0;i<sizeof(locations)/sizeof(locations[0]);i++) {
   uint8_t *p=tse+locations[i];field("PatchSite.RVA",locations[i]);
   field("  present",memory_present(p,32,0));field("  writable_now",memory_present(p,32,1));
   if(attr && attr->get) {uint64_t value=0;e=attr->get(attr,(UN)p&~4095ULL,4096,&value);status("  attribute_status",e);if(!FAILED(e))field("  attributes",value);}
  }
  field("AMITSE.stage",*(uint32_t *)(tse+0x82628));
  emit("AMITSE.browser_prologue=");for(unsigned i=0;i<18;i++)hex(tse[0xe208+i],2);emit("\r\n");
  emit("AMITSE.frame_prologue=");for(unsigned i=0;i<15;i++)hex(tse[0x15370+i],2);emit("\r\n");
  for(unsigned i=2;i<sizeof(locations)/sizeof(locations[0]);i++) {field("Slot.RVA",locations[i]);owner("  target",*(void **)(tse+locations[i]));}
 }
 if(st->rt && memory_present(st->rt,0x60,0)) {
  P4GETVAR get=*(P4GETVAR *)((uint8_t *)st->rt+0x48);
  field("RuntimeTable.writable_now",memory_present(st->rt,0x88,1));
  if(get) {
   uint8_t value=0;UN size=1;uint32_t attrs=0;
   e=get((C16 *)L"SecureBoot",&global_guid,&attrs,&size,&value);status("SecureBoot.read",e);if(!FAILED(e))field("SecureBoot",value);
   size=1;e=get((C16 *)L"SetupMode",&global_guid,&attrs,&size,&value);status("SetupMode.read",e);if(!FAILED(e))field("SetupMode",value);
   variable_info(get,"Credential.metadata",(C16 *)L"AiTweakerPassword1904",&credential_guid);
   variable_info(get,"OCMR.metadata",(C16 *)L"VARSTORE_OCMR_SETTINGS_NAME",&oc_guid);
   variable_info(get,"SocketMemory.metadata",(C16 *)L"SocketMemoryConfig",&memory_guid);
  }
 }
 emit("P4_WRITES=NONE\r\nP4_PREFLIGHT_END\r\n");
}

/* P4 adds read-only RuntimeServices metadata queries. */
ES EA efi_main(HANDLE image,ST *system_table) {
    (void)image;st=system_table;
    if(!st||!st->bs)return ERR(2);
    if(!st->bs->allocate_pool||!st->bs->free_pool||!st->bs->handle_protocol||
       !st->bs->locate_handles||!st->bs->locate_protocol||!st->bs->stall)return ERR(3);
    loglen=0;truncated=0;warnings=0;known_modules=0;hii_valid=0;images=0;image_count=0;
    screen("Ai Tweaker P4 - read-only lock preflight...\r\n");
    emit("AITWEAKER-PROBE-P3-KVM\r\nRead-only interface inventory. No password values collected.\r\n");
    typedef ES (EA *WD)(UN,uint64_t,UN,C16 *);
    ES watchdog=st->bs->set_watchdog?((WD)st->bs->set_watchdog)(0,0,0,0):ERR(3);
    if(FAILED(watchdog))warning("Watchdog.disable",watchdog);
    else status("Watchdog.disable",watchdog);
    inspect_images();inspect_protocols();inspect_hii();inspect_preflight();
    if(images)release(images);
    images=0;image_count=0;
    if(!hii_valid)warnings++;
    emit("Collection.warnings=");number(warnings);emit("\r\n");
    emit(warnings?"COLLECTION_STATUS=PARTIAL\r\n":"COLLECTION_STATUS=COMPLETE\r\n");
    emit("PROBE_COMPLETE\r\n");
    if(truncated){screen("Log exceeded 64 KiB. Incomplete inventory NOT exported.\r\n");return ERR(9);}
    return kvm_present(st,logbuf,loglen,warnings);
}
