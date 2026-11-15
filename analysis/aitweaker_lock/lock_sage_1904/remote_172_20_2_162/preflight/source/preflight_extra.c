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
 emit("P4_PREFLIGHT_BEGIN\r\nVariant=W790E_SAGE_SE_1904_READONLY\r\n");
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
 IMAGE_INFO info;int exact=tse&&probe_image(tse,tse_size,&info)&&info.text_crc==0x8a65ad70;
 field("AMITSE.exact_1904_fingerprint",exact);
 if(exact && tse_size>0x93950) {
  const uint32_t locations[]={0xe1b8,0x15320,0x6b928,0x6b930,0x6b840,0x7d4f8,0x837d8};
  for(unsigned i=0;i<sizeof(locations)/sizeof(locations[0]);i++) {
   uint8_t *p=tse+locations[i];field("PatchSite.RVA",locations[i]);
   field("  present",memory_present(p,32,0));field("  writable_now",memory_present(p,32,1));
   if(attr && attr->get) {uint64_t value=0;e=attr->get(attr,(UN)p&~4095ULL,4096,&value);status("  attribute_status",e);if(!FAILED(e))field("  attributes",value);}
  }
  field("AMITSE.stage",*(uint32_t *)(tse+0x83468));
  emit("AMITSE.browser_prologue=");for(unsigned i=0;i<18;i++)hex(tse[0xe1b8+i],2);emit("\r\n");
  emit("AMITSE.frame_prologue=");for(unsigned i=0;i<15;i++)hex(tse[0x15320+i],2);emit("\r\n");
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
