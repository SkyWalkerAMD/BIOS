/* One explicit, exact-target NII -> SNP attachment. No recursive ConnectController,
 * IP stack, NVRAM configuration, physical NIC selection, or driver unload. */
#include "snp_stage.h"
#include "snp_image.h"
static GUID nii31={0x1aced566,0x76ed,0x4218,{0xbc,0x81,0x76,0x7f,0x1f,0x97,0x7a,0x89}};
static GUID dp={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID snp={0xa19832b9,0xac25,0x11d3,{0x9a,0x2d,0,0x90,0x27,0x3f,0xc1,0x4d}};
static GUID binding_guid={0x18a031ab,0xb443,0x4d1a,{0xa5,0xc0,0x0c,0x09,0x26,0x1e,0x9f,0x71}};
static GUID marker_guid={0xb2781e1d,0xbcc6,0x470b,{0xaa,0x41,0x43,0x51,0x6d,0x56,0xb0,0xe2}};
static GUID nsvar={0xd1405d16,0x7afc,0x4695,{0xbb,0x12,0x41,0x45,0x9d,0x36,0x95,0xa2}};
static GUID dpc={0x480f8ae9,0x0c46,0x4aa9,{0xbc,0x89,0xdb,0x9f,0xba,0x61,0x98,0x06}};
static GUID mnp={0xf36ff770,0xa7e1,0x42cf,{0x9e,0xd2,0x56,0xf0,0xf2,0x71,0xf4,0x4c}};
static GUID arp={0xf44c00ee,0x1f2c,0x4a00,{0xaa,0x09,0x1c,0x9f,0x3e,0x08,0x00,0xa3}};
static GUID ip4={0xc51711e7,0xb4bf,0x404a,{0xbf,0xb8,0x0a,0x04,0x8e,0xf1,0xff,0xe4}};
static GUID tcp4={0x00720665,0x67eb,0x4a99,{0xba,0xf7,0xd3,0xc3,0x3a,0x1c,0x7c,0xc9}};
typedef struct DB DB;
struct DB{ES (EA *supported)(DB *,HANDLE,void *);ES (EA *start)(DB *,HANDLE,void *);void *stop;uint32_t version;HANDLE image,binding;};
typedef struct {uint64_t revision,id,image;uint32_t image_size;uint8_t tag[4],type,major,minor,ipv6;uint16_t ifnum;} NII;
typedef struct {uint32_t magic,state;HANDLE driver,controller;} MARKER;
OFF(DB,image,32);OFF(DB,binding,40);OFF(NII,tag,28);OFF(NII,ifnum,36);
_Static_assert(sizeof(DB)==48,"DriverBinding ABI");
uint32_t probe_crc32(const void *,size_t);
static UN path_length(const uint8_t *p){
 UN total=0;if(!p)return 0;
 for(unsigned i=0;i<64&&total<2048;i++){
  unsigned n=u16(p+total+2);if(n<4||n>256||n>2048-total)return 0;
  if(p[total]==0x7f)return p[total+1]==0xff&&n==4?total+4:0;total+=n;
 }return 0;
}
static HANDLE target_nii(int verbose){
 HANDLE usb[2];if(!usb_target_handles(usb))return 0;
 uint8_t *up=0;if(FAILED(gST->bs->handle_protocol(usb[0],&dp,(void **)&up)))return 0;
 UN un=path_length(up);if(un<4)return 0;
 HANDLE *hs=0,result=0;UN count=0,matches=0;ES e=gST->bs->locate_handles(2,&nii31,0,&count,&hs);
 if(verbose)status("I3A_NII31_COUNT",FAILED(e)?e:count);
 if(!FAILED(e)&&count<=128&&hs)for(UN i=0;i<count;i++){
  uint8_t *p=0;NII *n=0;
  if(FAILED(gST->bs->handle_protocol(hs[i],&dp,(void **)&p))||FAILED(gST->bs->handle_protocol(hs[i],&nii31,(void **)&n))||!n)continue;
  UN pn=path_length(p),prefix=un-4;
  if(pn!=un+37||!eq(p,up,prefix)||p[prefix]!=3||p[prefix+1]!=11||u16(p+prefix+2)!=37)continue;
  if(verbose){status("I3A_INTERNAL_NII_REVISION",n->revision);status("I3A_INTERNAL_NII_TYPE",n->type);status("I3A_INTERNAL_NII_MAJOR",n->major);status("I3A_INTERNAL_NII_MINOR",n->minor);logtext("I3A_INTERNAL_NII_TAG=");logbytes(n->tag,4);}
  if(n->revision<0x00020000||n->type!=1||n->major!=3||n->minor<1||!eq(n->tag,"UNDI",4))continue;
  result=hs[i];matches++;
 }
 if(hs)gST->bs->free_pool(hs);if(verbose)status("I3A_UNIQUE_INTERNAL_NII",matches==1);
 return matches==1?result:0;
}
static void count_proto(const char *name,GUID *guid){HANDLE *hs=0;UN n=0;ES e=gST->bs->locate_handles(2,guid,0,&n,&hs);status(name,FAILED(e)?e:n);if(hs)gST->bs->free_pool(hs);}
void snp_stage_inventory(void){
 HANDLE h=target_nii(1);void *p=0;
 status("I3A_INTERNAL_NII_SNP",h?gST->bs->handle_protocol(h,&snp,&p):ERR(14));
 status("I3A_DPC_PROTOCOL",gST->bs->locate_protocol(&dpc,0,&p));
 count_proto("I3A_MNP_BINDINGS",&mnp);count_proto("I3A_ARP_BINDINGS",&arp);count_proto("I3A_IP4_BINDINGS",&ip4);count_proto("I3A_TCP4_BINDINGS",&tcp4);
}
ES snp_stage_load(HANDLE image,FILEP *root){
 if(!i3_target_valid()||!root)return ERR(15);HANDLE controller=target_nii(1);if(!controller)return ERR(15);
 void *p=0;ES e=gST->bs->handle_protocol(controller,&snp,&p);if(!FAILED(e)&&p)return ERR(20);
 if(e!=ERR(3)&&e!=ERR(14))return FAILED(e)?e:ERR(33);
 uint8_t config[8]={0};UN size=sizeof(config);uint32_t attr=0;
 e=gST->rt->get_variable(W("NetworkStackVar"),&nsvar,&attr,&size,config);status("I3A_NETWORK_FLAG_READ",e);
 if(e||size!=8||config[0]>1)return e?e:ERR(33);
 MARKER *old=0;e=gST->bs->locate_protocol(&marker_guid,0,(void **)&old);if(e!=ERR(14))return ERR(20);
 FILEP *f=0;e=root->open(root,&f,W("\\EFI\\BOOT\\I3ASNP.EFI"),1,0);if(FAILED(e)||!f)return FAILED(e)?e:ERR(14);
 uint8_t *bytes=0;UN n=I3A_SNP_BYTES+1;e=gST->bs->allocate_pool(4,n,(void **)&bytes);if(FAILED(e)){f->close(f);return e;}
 e=f->read(f,&n,bytes);ES close=f->close(f);if(!FAILED(e)&&FAILED(close))e=close;
 if(FAILED(e)||n!=I3A_SNP_BYTES||probe_crc32(bytes,n)!=I3A_SNP_CRC32){gST->bs->free_pool(bytes);return FAILED(e)?e:ERR(33);}
 MARKER *state=0;e=gST->bs->allocate_pool(4,sizeof(*state),(void **)&state);if(FAILED(e)){gST->bs->free_pool(bytes);return e;}
 memset(state,0,sizeof(*state));state->magic=0x41335053;state->controller=controller;HANDLE marker=0;
 e=gST->bs->install_protocol(&marker,&marker_guid,0,state);if(FAILED(e)){gST->bs->free_pool(state);gST->bs->free_pool(bytes);return e;}state->state=1;
 e=gST->bs->load_image(0,image,0,bytes,n,&state->driver);gST->bs->free_pool(bytes);status("I3A_SNP_LOAD_IMAGE",e);if(FAILED(e))return e;
 e=gST->bs->start_image(state->driver,0,0);status("I3A_SNP_START_IMAGE",e);if(FAILED(e))return e;state->state=2;
 DB *driver=0;e=gST->bs->handle_protocol(state->driver,&binding_guid,(void **)&driver);status("I3A_SNP_DRIVER_BINDING",e);
 if(FAILED(e)||!driver||!driver->supported||!driver->start||driver->image!=state->driver||driver->binding!=state->driver)return FAILED(e)?e:ERR(33);
 /* Directly invoke this verified binding only. ConnectController's priority list
  * is not an allowlist and could dispatch unrelated drivers on the controller. */
 e=driver->supported(driver,controller,0);status("I3A_SNP_BINDING_SUPPORTED",e);if(FAILED(e))return e;
 e=driver->start(driver,controller,0);status("I3A_SNP_BINDING_START",e);state->state=3;if(FAILED(e))return e;
 p=0;e=gST->bs->handle_protocol(controller,&snp,&p);status("I3A_SNP_PUBLISHED",e);if(!FAILED(e)&&!p)return ERR(33);
 logtext("I3A_SNP_ONLY_RAM_SESSION_NO_IP_STACK_STARTED\r\n");return e;
}
