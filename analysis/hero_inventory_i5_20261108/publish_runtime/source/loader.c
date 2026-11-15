/* BMC-only RAM network preparation at TPL_APPLICATION.
 * No ConnectController recursion, PXE driver, SetVariable, or physical NIC bind.
 * Private driver images remain resident until reset.
 */
#include "i5.h"
#include "driver_images.h"
static GUID binding_guid={0x18a031ab,0xb443,0x4d1a,{0xa5,0xc0,0x0c,0x09,0x26,0x1e,0x9f,0x71}};
static GUID nii_guid={0x1aced566,0x76ed,0x4218,{0xbc,0x81,0x76,0x7f,0x1f,0x97,0x7a,0x89}};
static GUID dp_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID nsvar={0xd1405d16,0x7afc,0x4695,{0xbb,0x12,0x41,0x45,0x9d,0x36,0x95,0xa2}};
static GUID dpc_guid={0x480f8ae9,0x0c46,0x4aa9,{0xbc,0x89,0xdb,0x9f,0xba,0x61,0x98,0x06}};
static GUID tls_guid={0x952cb795,0xff36,0x48cf,{0xa2,0x49,0x4d,0xf4,0x86,0xd6,0xab,0x8d}};
static GUID services[]={
 {0xa19832b9,0xac25,0x11d3,{0x9a,0x2d,0,0x90,0x27,0x3f,0xc1,0x4d}},
 {0xf36ff770,0xa7e1,0x42cf,{0x9e,0xd2,0x56,0xf0,0xf2,0x71,0xf4,0x4c}},
 {0xf44c00ee,0x1f2c,0x4a00,{0xaa,0x09,0x1c,0x9f,0x3e,0x08,0,0xa3}},
 {0xc51711e7,0xb4bf,0x404a,{0xbf,0xb8,0x0a,0x04,0x8e,0xf1,0xff,0xe4}},
 {0x00720665,0x67eb,0x4a99,{0xba,0xf7,0xd3,0xc3,0x3a,0x1c,0x7c,0xc9}}
};
typedef struct DB DB;
struct DB{ES (EA *supported)(DB *,HANDLE,void *);ES (EA *start)(DB *,HANDLE,void *);ES (EA *stop)(DB *,HANDLE,UN,HANDLE *);uint32_t version;HANDLE image,binding;};
typedef struct {uint64_t revision,id,image;uint32_t image_size;uint8_t tag[4],type,major,minor,ipv6;uint16_t ifnum;} NII;
OFF(DB,image,32);OFF(DB,binding,40);OFF(NII,tag,28);OFF(NII,ifnum,36);
static HANDLE loaded[8];static unsigned attempted;
static HANDLE allowed_usb[2],allowed_nii;
static GUID image_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
typedef struct {unsigned image,rva,supported,start,stop,version,mode;} BIND_SPEC;
/* Exact data structures in the source-hash-pinned PE images. mode 0 denies
 * TCP6 entirely; mode 1 is the one BMC NII; mode 2 is its USB interface pair. */
static const BIND_SPEC spec[]={
 {1,0x4ba0,0x7ac,0x8ac,0x1068,10,1},
 {2,0x61d0,0x6c8,0x734,0x968,10,1},
 {3,0x2e20,0x980,0xa04,0xab0,10,1},
 {4,0xbda0,0x7e8,0xdf8,0x1074,10,1},
 {5,0xad80,0xda4,0xe28,0xe64,10,0},
 {5,0xaec0,0xcc4,0xd48,0xd84,10,1},
 {6,0x22e0,0x960,0xa3c,0xe68,1,2},
 {7,0x2a20,0x5a0,0x61c,0x9d0,1,2}
};
typedef struct {DB *db;DB original;unsigned mode,disabled;} SCOPED;
static SCOPED scoped[8];
static SCOPED *scope_for(DB *db){for(unsigned i=0;i<8;i++)if(scoped[i].db==db)return &scoped[i];return 0;}
static int scope_allows(SCOPED *s,HANDLE h){return s&&!s->disabled&&((s->mode==1&&h==allowed_nii&&h)||(s->mode==2&&(h==allowed_usb[0]||h==allowed_usb[1])&&h));}
static ES EA scope_supported(DB *db,HANDLE h,void *path){SCOPED *s=scope_for(db);return scope_allows(s,h)?s->original.supported(db,h,path):ERR(3);}
static ES EA scope_start(DB *db,HANDLE h,void *path){SCOPED *s=scope_for(db);return scope_allows(s,h)?s->original.start(db,h,path):ERR(3);}
static ES EA scope_stop(DB *db,HANDLE h,UN count,HANDLE *children){SCOPED *s=scope_for(db);return scope_allows(s,h)?s->original.stop(db,h,count,children):ERR(3);}
static ES scope_before_start(unsigned index){
 if(!index)return 0;LOADED *li=0;ES e=gST->bs->handle_protocol(loaded[index],&image_guid,(void **)&li);
 if(FAILED(e)||!li||!li->image_base||li->image_size>1024*1024)return FAILED(e)?e:ERR(33);
 UN base=(UN)li->image_base;
 for(unsigned i=0;i<8;i++)if(spec[i].image==index){
  const BIND_SPEC *p=&spec[i];if(scoped[i].db||p->rva>li->image_size||sizeof(DB)>li->image_size-p->rva)return ERR(33);
  DB *db=(DB *)(base+p->rva);
  if((UN)db->supported!=base+p->supported||(UN)db->start!=base+p->start||(UN)db->stop!=base+p->stop||db->version!=p->version||db->image||db->binding)return ERR(33);
  scoped[i].db=db;scoped[i].original=*db;scoped[i].mode=p->mode;
 }
 /* The entire image was validated before mutating any protocol pointer. */
 for(unsigned i=0;i<8;i++)if(spec[i].image==index){DB *db=scoped[i].db;db->supported=scope_supported;db->start=scope_start;db->stop=scope_stop;}
 return 0;
}
static int scope_after_start(unsigned index){
 int valid=1;for(unsigned i=0;i<8;i++)if(spec[i].image==index){DB *db=scoped[i].db;
  if(!db||db->supported!=scope_supported||db->start!=scope_start||db->stop!=scope_stop)valid=0;
 }
 if(!valid)for(unsigned i=0;i<8;i++)if(spec[i].image==index&&scoped[i].db){
  scoped[i].disabled=1;DB *db=scoped[i].db;db->supported=scope_supported;db->start=scope_start;db->stop=scope_stop;
 }
 return valid;
}
uint32_t probe_crc32(const void *,size_t);
UN i5_current_tpl(void){
 if(!gST||!gST->bs||!gST->bs->raise_tpl||!gST->bs->restore_tpl)return ~(UN)0;
 UN old=gST->bs->raise_tpl(31);gST->bs->restore_tpl(old);return old;
}
static UN path_length(const uint8_t *p){
 UN total=0;if(!p)return 0;
 for(unsigned i=0;i<64&&total<2048;i++){
  unsigned n=u16(p+total+2);if(n<4||n>256||n>2048-total)return 0;
  if(p[total]==0x7f)return p[total+1]==0xff&&n==4?total+4:0;total+=n;
 }return 0;
}
static HANDLE internal_nii(HANDLE control){
 uint8_t *prefix=0;if(FAILED(gST->bs->handle_protocol(control,&dp_guid,(void **)&prefix)))return 0;
 UN un=path_length(prefix);if(un<4)return 0;
 HANDLE *handles=0,result=0;UN count=0;unsigned matches=0;
 ES e=gST->bs->locate_handles(2,&nii_guid,0,&count,&handles);
 if(!FAILED(e)&&handles&&count<=128)for(UN i=0;i<count;i++){
  uint8_t *path=0;NII *nii=0;
  if(FAILED(gST->bs->handle_protocol(handles[i],&dp_guid,(void **)&path))||
     FAILED(gST->bs->handle_protocol(handles[i],&nii_guid,(void **)&nii))||!nii)continue;
  UN pn=path_length(path),n=un-4;
  if(pn!=un+37||!eq(path,prefix,n)||path[n]!=3||path[n+1]!=11||u16(path+n+2)!=37)continue;
  if(nii->revision<0x20000||nii->type!=1||nii->major!=3||nii->minor<1||!eq(nii->tag,"UNDI",4))continue;
  result=handles[i];matches++;
 }
 if(handles)gST->bs->free_pool(handles);status("I5_UNIQUE_INTERNAL_NII",matches);
 return matches==1?result:0;
}
static ES load_one(HANDLE parent,unsigned i){
 if(i>=8||loaded[i]||i5_current_tpl()!=4||!i5_source_valid())return ERR(15);
 const I5_IMAGE *p=&images[i];logtext("I5_LOAD_NAME=");logtext(p->name);logtext("\r\n");
 if(probe_crc32(p->bytes,p->length)!=p->crc)return ERR(33);
 ES e=gST->bs->load_image(0,parent,0,(void *)p->bytes,p->length,&loaded[i]);status("I5_LOAD_IMAGE",e);
 if(FAILED(e))return e;
 e=scope_before_start(i);status("I5_SCOPE_INSTALLED_BEFORE_START",e);if(FAILED(e))return e;
 e=gST->bs->start_image(loaded[i],0,0);status("I5_START_IMAGE",e);
 if(!scope_after_start(i))return ERR(33);return e;
}
/* DriverBinding handles may differ from ImageHandle (TCP4/TCP6 are separate).
 * Only bindings from the one hash-checked private image are ever called. */
static ES bind_one(unsigned image_index,HANDLE controller,int allow_unsupported){
 if(image_index>=8||!loaded[image_index]||!controller||i5_current_tpl()!=4)return ERR(15);
 HANDLE *handles=0;UN count=0;unsigned supported=0;ES result=ERR(3);
 ES e=gST->bs->locate_handles(2,&binding_guid,0,&count,&handles);
 if(FAILED(e))return e;if(!handles||count>512){if(handles)gST->bs->free_pool(handles);return ERR(33);}
 for(UN i=0;i<count;i++){
  DB *db=0;if(FAILED(gST->bs->handle_protocol(handles[i],&binding_guid,(void **)&db))||!db)continue;
  if(db->image!=loaded[image_index]||db->binding!=handles[i]||!db->supported||!db->start)continue;
  e=db->supported(db,controller,0);status("I5_BIND_SUPPORTED",e);
  if(e==ERR(3))continue;
  if(e==ERR(20)){supported++;result=0;continue;}
  if(FAILED(e)){result=e;break;}
  supported++;e=db->start(db,controller,0);status("I5_BIND_START",e);
  if(FAILED(e)&&e!=ERR(20)){result=e;break;}result=0;
 }
 gST->bs->free_pool(handles);
 return supported?result:(allow_unsupported?0:ERR(3));
}
ES i5_prepare_network(HANDLE parent){
 if(attempted)return ERR(20);attempted=1;
 if(i5_current_tpl()!=4||!i5_source_valid())return ERR(15);
 HANDLE usb[2];if(!usb_target_handles(usb))return ERR(14);
 allowed_usb[0]=usb[0];allowed_usb[1]=usb[1];
 void *p=0;ES e=gST->bs->locate_protocol(&tls_guid,0,&p);status("I5_NATIVE_TLS_AVAILABLE",e);
 if(FAILED(e)||!p)return FAILED(e)?e:ERR(14);
 uint8_t before[8]={0},after[8]={0};UN size=8;uint32_t attr=0,after_attr=0;
 e=gST->rt->get_variable(W("NetworkStackVar"),&nsvar,&attr,&size,before);status("I5_NETWORK_FLAG_READ",e);
 if(e||size!=8||before[0]>1)return e?e:ERR(33);
 status("I5_NETWORK_STACK_ORIGINAL_ENABLED",before[0]);
 p=0;e=gST->bs->locate_protocol(&dpc_guid,0,&p);
 if(e==ERR(14)){
  e=load_one(parent,0);if(FAILED(e))return e;
  e=gST->bs->locate_protocol(&dpc_guid,0,&p);
 }
 if(FAILED(e)||!p)return FAILED(e)?e:ERR(14);
 HANDLE controller=internal_nii(usb[0]);
 if(!controller){
  e=load_one(parent,6);if(FAILED(e))return e;e=load_one(parent,7);if(FAILED(e))return e;
  for(unsigned image=6;image<8;image++)for(unsigned n=0;n<2;n++){
   e=bind_one(image,usb[n],1);if(FAILED(e))return e;
  }
  controller=internal_nii(usb[0]);if(!controller)return ERR(14);
 }
 allowed_nii=controller;
 for(unsigned i=0;i<5;i++){
  p=0;e=gST->bs->handle_protocol(controller,&services[i],&p);status("I5_EXISTING_STAGE",e);
  if(!FAILED(e)&&p){logtext("I5_EXISTING_SERVICE_REUSED\r\n");continue;}
  if(e!=ERR(3)&&e!=ERR(14))return FAILED(e)?e:ERR(33);
  e=load_one(parent,i+1);if(FAILED(e))return e;
  e=bind_one(i+1,controller,0);if(FAILED(e))return e;
  p=0;e=gST->bs->handle_protocol(controller,&services[i],&p);status("I5_STAGE_PUBLISHED",e);
  if(FAILED(e)||!p)return FAILED(e)?e:ERR(33);
 }
 size=8;e=gST->rt->get_variable(W("NetworkStackVar"),&nsvar,&after_attr,&size,after);
 if(e||size!=8||after_attr!=attr||!eq(before,after,8)){status("I5_NETWORK_FLAG_CHANGED_UNEXPECTED",e?e:ERR(33));return e?e:ERR(33);}
 logtext("I5_NETWORK_STACK_VARIABLE_UNCHANGED\r\nI5_PRIVATE_RAM_STACK_ONLY_ON_VERIFIED_BMC_USB\r\n");
 network_inventory();return network_candidate()?0:ERR(14);
}
