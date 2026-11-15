/* Read-only firmware identity inventory; no entrypoint/driver/BMC/NV operations.
 * ABI: EDK2 edk2-stable202502 LoadedImage.h, FirmwareVolume2.h, DevicePath.h,
 * PiFirmwareFile.h and UefiSpec.h. See reference and provenance.json. */
#include "firmware_probe.h"

static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fv_guid={0x220e73b6,0x6bdb,0x4413,{0x84,5,0xb9,0x74,0xb1,8,0x61,0x9a}};
static GUID targets[]={
 {0x89924765,0xf984,0x4ad3,{0x83,0x9b,0x51,0xfd,0xce,0x37,0x8d,0x88}},
 {0x261135b0,0x7b73,0x49c0,{0xbc,0xc8,0x2f,0x9c,0xf4,0xee,0xf1,0x9e}}
};
static const char *const labels[]={"R2","P5_P6"};
typedef struct FV FV;
struct FV {
 void *get_attributes,*set_attributes;
 ES (EA *read_file)(FV *,const GUID *,void **,UN *,uint8_t *,uint32_t *,uint32_t *);
 ES (EA *read_section)(FV *,const GUID *,uint8_t,UN,void **,UN *,uint32_t *);
 void *write_file,*get_next_file;uint32_t key_size;HANDLE parent;void *get_info,*set_info;
};
typedef ES (EA *GET_MAP)(UN *,void *,UN *,UN *,uint32_t *);
OFF(FV,read_file,16);OFF(FV,read_section,24);OFF(FV,key_size,48);OFF(FV,parent,56);
_Static_assert(sizeof(FV)==80,"FV2 x64 ABI");
OFF(LOADED,filepath,32);OFF(LOADED,image_base,64);OFF(LOADED,image_size,72);
OFF(BS,get_memory_map,56);

typedef struct {ST *st;FP_APPEND append;void *ctx;size_t log_used,map_size,desc_size;
 unsigned incomplete,loaded[2],fv_files[2],pe_sections[2],budget,matched;} STATE;
static uint64_t memory_map[FP_MAP_CAP/8];
static uint8_t path_copy[FP_PATH_CAP];
static struct {uint8_t before[16],data[FP_FILE_CAP],after[16];} section_buffer;
static unsigned busy;
static uint32_t r32(const uint8_t *p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static uint64_t r64(const uint8_t *p){return r32(p)|((uint64_t)r32(p+4)<<32);}

/* Only allocated RAM types 1..6 or ACPI reclaim/NVS; never MMIO, reserved,
 * conventional/free RAM, unusable or read-protected descriptors. */
int fp_range_readable(const uint8_t *map,size_t bytes,size_t stride,uint64_t at,size_t n){
 if(!map||!bytes||bytes>FP_MAP_CAP||stride<40||stride>256||stride%8||bytes%stride||bytes/stride>2048||!at||!n||at+(uint64_t)n<at)return 0;
 uint64_t end=at+(uint64_t)n;unsigned spans=0;
 while(at<end&&spans++<=2048){
  uint64_t advance=at;
  for(size_t off=0;off<bytes;off+=stride){
   const uint8_t *p=map+off;uint32_t type=r32(p);uint64_t start=r64(p+8),pages=r64(p+24),attr=r64(p+32);
   if(!((type>=1&&type<=6)||type==9||type==10)||(attr&0x2000)||!pages||pages>(UINT64_MAX-start)/4096)continue;
   uint64_t limit=start+pages*4096;
   if(at>=start&&at<limit&&limit>advance)advance=limit;
  }
  if(advance==at)return 0;at=advance<end?advance:end;
 }
 return at==end;
}

/* A successful return requires a complete path ending in End Entire (7F/FF).
 * Media PIWG Firmware File nodes are exactly 20 bytes: header plus GUID. */
int fp_path_targets(const uint8_t *p,size_t n,unsigned *mask){
 if(mask)*mask=0;if(!p||!mask||n<4||n>FP_PATH_CAP)return 0;
 size_t off=0;unsigned nodes=0,found=0;
 while(off+4<=n&&nodes++<128){
  unsigned len=(unsigned)p[off+2]|((unsigned)p[off+3]<<8);
  if(len<4||len>n-off)return 0;
  if(p[off]==0x7f){
   if(len!=4)return 0;
   if(p[off+1]==0xff){*mask=found;return 1;}
   if(p[off+1]!=1)return 0;
  }
  if(p[off]==4&&p[off+1]==6){
   if(len!=20)return 0;
   for(unsigned j=0;j<2;j++)if(eq(p+off+4,&targets[j],16))found|=1U<<j;
  }
  off+=len;
 }
 return 0;
}

static void output(STATE *s,const char *p,size_t n){
 if(n>131072U-s->log_used){s->incomplete=1;return;}s->append(s->ctx,p,n);s->log_used+=n;
}
static void add(STATE *s,const char *p){size_t n=0;while(p[n])n++;output(s,p,n);}
static void hex(STATE *s,uint64_t v,unsigned digits){char b[16];for(unsigned i=0;i<digits;i++)b[i]="0123456789ABCDEF"[(v>>((digits-1-i)*4))&15];output(s,b,digits);}
static void field(STATE *s,const char *p,uint64_t v){add(s,p);add(s,"=");hex(s,v,16);add(s,"\r\n");}
static int readable(STATE *s,const void *p,size_t n){return fp_range_readable((uint8_t *)memory_map,s->map_size,s->desc_size,(uint64_t)(UN)p,n);}
static int get_map(STATE *s){
 UN size=sizeof(memory_map),key=0,stride=0;uint32_t version=0;
 ES e=((GET_MAP)s->st->bs->get_memory_map)(&size,memory_map,&key,&stride,&version);
 field(s,"FP_MEMORY_MAP_STATUS",e);field(s,"FP_MEMORY_MAP_BYTES",size);field(s,"FP_MEMORY_MAP_STRIDE",stride);
 s->map_size=0;s->desc_size=0;
 if(e||version!=1||size>sizeof(memory_map)||stride<40||stride>256||stride%8||!size||size%stride||size/stride>2048){s->incomplete=1;return 0;}
 s->map_size=(size_t)size;s->desc_size=(size_t)stride;return 1;
}
static int copy_path(STATE *s,const uint8_t *p,unsigned *mask){
 size_t off=0;unsigned nodes=0;
 while(off+4<=FP_PATH_CAP&&nodes++<128){
  if((UN)p+off<(UN)p||!readable(s,p+off,4))return 0;
  unsigned len=p[off+2]|((unsigned)p[off+3]<<8);
  if(len<4||len>FP_PATH_CAP-off||!readable(s,p+off,len))return 0;
  memcpy(path_copy+off,p+off,len);off+=len;
  if(path_copy[off-len]==0x7f&&path_copy[off-len+1]==0xff)return fp_path_targets(path_copy,off,mask);
 }
 return 0;
}
static void free_handles(STATE *s,HANDLE *handles){
 if(handles){ES e=s->st->bs->free_pool(handles);field(s,"FP_HANDLES_FREE_STATUS",e);if(e)s->incomplete=1;}
}
static void scan_loaded(STATE *s){
 HANDLE *handles=0;UN count=0;unsigned bad_protocol=0,bad_path=0,scanned=0;
 ES e=s->st->bs->locate_handles(2,&loaded_guid,0,&count,&handles);
 field(s,"FP_LOADED_ENUM_STATUS",e);field(s,"FP_LOADED_HANDLE_COUNT",count);
 if(e){s->incomplete=1;free_handles(s,handles);return;}
 if(!get_map(s)||!handles||count>FP_HANDLE_CAP||!readable(s,handles,(size_t)count*sizeof(HANDLE))){s->incomplete=1;free_handles(s,handles);return;}
 for(UN i=0;i<count;i++){
  LOADED *image=0;unsigned mask=0;e=s->st->bs->handle_protocol(handles[i],&loaded_guid,(void **)&image);scanned++;
  if(e||!readable(s,image,sizeof(*image))){bad_protocol++;continue;}
  if(!image->filepath)continue;
  if(!copy_path(s,image->filepath,&mask)){bad_path++;continue;}
  if(!mask)continue;
  if(s->matched++>=16){s->incomplete=1;break;}
  for(unsigned j=0;j<2;j++)if(mask&(1U<<j)){
   s->loaded[j]++;add(s,"FP_LOADED_MATCH=");add(s,labels[j]);add(s,"\r\n");
   field(s,"FP_LOADED_HANDLE",(UN)handles[i]);field(s,"FP_LOADED_DEVICE",(UN)image->device);
   field(s,"FP_LOADED_BASE",(UN)image->image_base);field(s,"FP_LOADED_SIZE",image->image_size);
   if(image->image_size&&image->image_size<=FP_IMAGE_CAP&&image->image_size<=s->budget&&readable(s,image->image_base,(size_t)image->image_size)){
    uint32_t crc=probe_crc32(image->image_base,(size_t)image->image_size);s->budget-=(unsigned)image->image_size;
    field(s,"FP_LOADED_MEMORY_CRC32",crc);
   }else{add(s,"FP_LOADED_CRC_SKIPPED_BOUND_OR_MAP\r\n");s->incomplete=1;}
  }
 }
 field(s,"FP_LOADED_SCANNED",scanned);field(s,"FP_LOADED_PROTOCOL_UNREADABLE",bad_protocol);field(s,"FP_LOADED_PATH_UNREADABLE",bad_path);
 if(bad_protocol||bad_path)s->incomplete=1;free_handles(s,handles);
}
static int canaries(void){for(unsigned i=0;i<16;i++)if(section_buffer.before[i]!=0xa5||section_buffer.after[i]!=0xa5)return 0;return 1;}
static void scan_fv(STATE *s){
 HANDLE *handles=0;UN count=0;unsigned scanned=0;
 ES e=s->st->bs->locate_handles(2,&fv_guid,0,&count,&handles);
 field(s,"FP_FV_ENUM_STATUS",e);field(s,"FP_FV_HANDLE_COUNT",count);
 if(e){s->incomplete=1;free_handles(s,handles);return;}
 if(!get_map(s)||!handles||count>FP_FV_CAP||!readable(s,handles,(size_t)count*sizeof(HANDLE))){s->incomplete=1;free_handles(s,handles);return;}
 for(UN i=0;i<count;i++){
  FV *fv=0;e=s->st->bs->handle_protocol(handles[i],&fv_guid,(void **)&fv);scanned++;
  field(s,"FP_FV_INDEX",i);field(s,"FP_FV_PROTOCOL_STATUS",e);
  if(e||!readable(s,fv,sizeof(*fv))||!readable(s,(const void *)fv->read_file,1)||!readable(s,(const void *)fv->read_section,1)){s->incomplete=1;continue;}
  field(s,"FP_FV_HANDLE",(UN)handles[i]);field(s,"FP_FV_PARENT",(UN)fv->parent);
  for(unsigned j=0;j<2;j++){
   UN bytes=0;uint8_t type=0;uint32_t attributes=0,auth=0;
   /* Buffer == NULL requests metadata only; it cannot allocate file output. */
   e=fv->read_file(fv,&targets[j],0,&bytes,&type,&attributes,&auth);
   add(s,"FP_FV_TARGET=");add(s,labels[j]);add(s,"\r\n");field(s,"FP_FV_READFILE_STATUS",e);
   if(e){if(e!=ERR(14))s->incomplete=1;continue;}
   s->fv_files[j]++;field(s,"FP_FV_FILE_BYTES",bytes);field(s,"FP_FV_FILE_TYPE",type);field(s,"FP_FV_FILE_ATTRIBUTES",attributes);
   if(!bytes||bytes>FP_FILE_CAP||s->budget<FP_FILE_CAP){add(s,"FP_FV_SECTION_SKIPPED_BOUND\r\n");s->incomplete=1;continue;}
   memset(section_buffer.before,0xa5,16);memset(section_buffer.after,0xa5,16);
   void *buffer=section_buffer.data;UN size=FP_FILE_CAP;auth=0;
   e=fv->read_section(fv,&targets[j],0x10,0,&buffer,&size,&auth);
   field(s,"FP_FV_PE_STATUS",e);field(s,"FP_FV_PE_BYTES",size);field(s,"FP_FV_PE_AUTH",auth);
   if(buffer!=section_buffer.data||!canaries()){add(s,"FP_FV_PROVIDER_BUFFER_CONTRACT_FAILED\r\n");s->incomplete=1;goto finish;}
   /* Exact success only: EFI_WARN_BUFFER_TOO_SMALL is not a complete image. */
   if(e||!size||size>FP_FILE_CAP){s->incomplete=1;continue;}
   s->budget-=(unsigned)size;s->pe_sections[j]++;
   field(s,"FP_FV_PE_CRC32",probe_crc32(buffer,(size_t)size));
   const uint8_t *p=buffer;unsigned pe=0;
   if(size>=64&&p[0]=='M'&&p[1]=='Z'){
    uint32_t at=r32(p+60);if(at<=size-24&&eq(p+at,"PE\0\0",4)){
     pe=1;field(s,"FP_FV_PE_MACHINE",p[at+4]|((unsigned)p[at+5]<<8));
    }
   }
   field(s,"FP_FV_PE_HEADER_VALID",pe);
  }
 }
finish:
 field(s,"FP_FV_SCANNED",scanned);free_handles(s,handles);
}
ES firmware_probe(ST *st,FP_APPEND append,void *context){
 if(!st||!st->bs||!append||!st->bs->get_memory_map||!st->bs->locate_handles||!st->bs->handle_protocol||!st->bs->free_pool)return ERR(2);
 if(busy)return ERR(20);busy=1;
 STATE s={.st=st,.append=append,.ctx=context,.budget=FP_CRC_BUDGET};
 add(&s,"FIRMWARE_PROBE_I1_BEGIN\r\n");
 add(&s,"R2_FFS_GUID=89924765-f984-4ad3-839b-51fdce378d88\r\nP5_P6_FFS_GUID=261135b0-7b73-49c0-bcc8-2f9cf4eef19e\r\n");
 scan_loaded(&s);scan_fv(&s);
 field(&s,"FP_R2_LOADED_MATCHES",s.loaded[0]);field(&s,"FP_P5_P6_LOADED_MATCHES",s.loaded[1]);
 field(&s,"FP_R2_FV_FILES",s.fv_files[0]);field(&s,"FP_P5_P6_FV_FILES",s.fv_files[1]);
 field(&s,"FP_R2_PE_SECTIONS",s.pe_sections[0]);field(&s,"FP_P5_P6_PE_SECTIONS",s.pe_sections[1]);
 field(&s,"FP_ENUM_OR_READ_INCOMPLETE",s.incomplete);
 add(&s,"Visible FV files only; absence does not prove RC version or flash contents.\r\n");
 add(&s,"Loaded memory CRC includes relocations/mutable state; use FV PE CRC for file comparison.\r\n");
 add(&s,"LoadedImage presence does not prove entrypoint success; no initialization invoked.\r\nFIRMWARE_PROBE_I1_END\r\n");
 busy=0;return s.incomplete?ERR(33):0;
}
