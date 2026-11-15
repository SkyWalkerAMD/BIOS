/* Read-only .15 pre-load evidence. No MMIO, PCI write, IPMI, variable write,
 * run callback, event creation/signalling, host reset or firmware update. */
#include "preflight.h"
#include "hero_bmc_pci.h"
char preflight_audit[65536];UN preflight_bytes;
unsigned preflight_bad;
uint32_t preflight_source_bytes,preflight_source_crc;
static GUID pci_guid={0x4cf5b200,0x68b8,0x4ca5,{0x9e,0xec,0xb2,0x3e,0x3f,0x50,0x02,0x9a}};
static GUID cfg_guid=CFG_GUID_INIT;
static GUID enum_guid={0x30cfe3e7,0x3de1,0x4586,{0xbe,0x20,0xde,0xab,0xa1,0xb3,0xb7,0x93}};
void preflight_reset_log(void){preflight_bytes=0;preflight_bad=0;preflight_audit[0]=0;}
void logtext(const char *s){while(*s){if(preflight_bytes>=sizeof(preflight_audit)-1){preflight_bad=1;break;}preflight_audit[preflight_bytes++]=*s++;}preflight_audit[preflight_bytes]=0;}
void loghex(uint64_t value,unsigned digits){if(digits>16){preflight_bad=1;return;}char text[17];for(unsigned i=0;i<digits;i++)text[i]="0123456789ABCDEF"[(value>>((digits-1-i)*4))&15];text[digits]=0;logtext(text);}
void logbytes(const uint8_t *p,size_t bytes){for(size_t i=0;i<bytes;i++){if(i)logtext(" ");loghex(p[i],2);}logtext("\r\n");}
uint16_t u16(const uint8_t *p){return p[0]|((uint16_t)p[1]<<8);}
uint32_t u32(const uint8_t *p){return u16(p)|((uint32_t)u16(p+2)<<16);}
uint64_t u64(const uint8_t *p){return u32(p)|((uint64_t)u32(p+4)<<32);}
static void code(const char *name,ES value){logtext(name);loghex(value,16);logtext("\r\n");}
static ES pci_capture(PREFLIGHT *v){
 void *marker=0;ES e=gST->bs->locate_protocol(&enum_guid,0,&marker);code("PCI_ENUMERATION_STATUS=",e);if(e)return e;
 HANDLE *handles=0;UN count=0;unsigned matches=0;PCI *card=0;int complete=1;
 e=gST->bs->locate_handles(2,&pci_guid,0,&count,&handles);
 code("PCI_ENUM_STATUS=",e);logtext("PCI_ENUM_COUNT=");loghex(count,8);logtext("\r\n");
 if(e||!handles||!count||count>4096){if(handles)gST->bs->free_pool(handles);return e?e:ERR(33);}
 if(!memory_readable(handles,count*sizeof(HANDLE))){gST->bs->free_pool(handles);return ERR(33);}
 for(UN i=0;i<count;i++){
  PCI *p=0;uint8_t config[64];
  e=gST->bs->handle_protocol(handles[i],&pci_guid,(void **)&p);
  if(e||!p||!memory_readable(p,sizeof(*p))||!p->pci.read){complete=0;break;}
  e=p->pci.read(p,0,0,sizeof(config),config);if(e){complete=0;break;}
  if(u32(config)==0x24021a03U){matches++;card=p;memcpy(v->pci_config,config,sizeof(config));}
 }
 ES freed=gST->bs->free_pool(handles);code("PCI_ENUM_LAST_STATUS=",e);code("PCI_ENUM_FREE_STATUS=",freed);
 logtext("PCI_MATCHES=");loghex(matches,4);logtext(" COMPLETE=");loghex(complete,1);logtext("\r\n");
 if(!complete||freed||matches!=1||!hero_bmc_pci_identity(v->pci_config))return ERR(33);
 if(!card->pci.write||!card->mem.read||!card->mem.write||!card->location||!card->bar_attributes)return ERR(33);
 e=card->location(card,&v->segment,&v->bus,&v->device,&v->function);
 code("PCI_LOCATION_STATUS=",e);logtext("PCI_BDF=");loghex(v->segment,4);logtext(":");loghex(v->bus,16);logtext(":");loghex(v->device,2);logtext(".");loghex(v->function,1);logtext("\r\n");
 if(e||!hero_bmc_pci_location(v->segment,v->bus,v->device,v->function))return ERR(33);
 void *resource=0;uint64_t supported=0;e=card->bar_attributes(card,1,&supported,&resource);code("BAR1_STATUS=",e);
 int ok=!e&&resource&&memory_readable(resource,46);
 if(ok){memcpy(v->bar1_descriptor,resource,46);ok=hero_bmc_pci_bar1(v->bar1_descriptor,v->pci_config);}
 if(resource){freed=gST->bs->free_pool(resource);code("BAR1_FREE_STATUS=",freed);if(freed)ok=0;}
 logtext("PCI_CONFIG ");logbytes(v->pci_config,64);logtext("BAR1_DESCRIPTOR ");logbytes(v->bar1_descriptor,46);
 return ok?0:ERR(33);
}
static ES config_capture(PREFLIGHT *v){
 uint8_t bytes[8]={0};UN n=sizeof(bytes);uint32_t attrs=0;
 ES e=gST->rt->get_variable(W("HeroIpmiCfg"),&cfg_guid,&attrs,&n,bytes);v->config_status=e;
 v->config_bytes=(uint32_t)n;v->config_attributes=attrs;memcpy(v->configuration,bytes,sizeof(bytes));
 code("HERO_IPMI_CFG_STATUS=",e);logtext("CFG_BYTES=");loghex(n,8);logtext(" ATTRS=");loghex(attrs,8);logtext(" RAW=");logbytes(bytes,sizeof(bytes));
 if(e==ERR(14)){logtext("CFG_ABSENT: R5 default enabled; no variable is created by preflight or driver entry.\r\n");return 0;}
 CONFIG expected={CFG_MAGIC,1,1,{0,0}};
 if(e||n!=8||attrs!=3||!eq(bytes,&expected,8))return ERR(15);
 return 0;
}
static ES lock_capture(const C16 *name){
 uint8_t data[8]={0};UN n=sizeof(data);uint32_t attrs=0;
 ES e=gST->rt->get_variable((C16 *)name,&cfg_guid,&attrs,&n,data);
 logtext("LOCK_STATUS=");loghex(e,16);logtext(" BYTES=");loghex(n,8);logtext(" ATTRS=");loghex(attrs,8);logtext("\r\n");
 return e;
}
ES preflight_capture(PREFLIGHT *v){
 if(!v||!gST||!gST->bs||!gST->rt||!gST->rt->get_variable)return ERR(2);
 if(preflight_bad||preflight_bytes>sizeof(preflight_audit)-8192)return ERR(5);
 memset(v,0,sizeof(*v));logtext("HERO15_R5_PREFLIGHT_BEGIN: no KCS or writes\r\n");
 v->identity_status=identity_check();v->source_bytes=preflight_source_bytes;v->source_crc=preflight_source_crc;
 code("IDENTITY_STATUS=",v->identity_status);if(v->identity_status)return v->identity_status;
 v->pci_status=pci_capture(v);code("PCI_PREFLIGHT_STATUS=",v->pci_status);if(v->pci_status)return v->pci_status;
 ES config=config_capture(v);
 logtext("HeroIpmiAttempt ");v->sensor_lock_status=lock_capture(W("HeroIpmiAttempt"));
 logtext("HeroIpmiDmiAttempt ");v->dashboard_lock_status=lock_capture(W("HeroIpmiDmiAttempt"));
 if(config||v->sensor_lock_status!=ERR(14)||v->dashboard_lock_status!=ERR(14))return ERR(15);
 if(preflight_bad)return ERR(5);
 logtext("PREFLIGHT_SAFE: exact local identity; unique PCI; enabled/default config; no attempt latch.\r\n");return 0;
}
