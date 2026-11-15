/* Fixed-payload capacity diagnostic bootstrap. No interactive shell or fallback.
 * All payload file I/O is read-only through this image's own DeviceHandle.
 * Hashes pin the reviewed bytes; this is not a substitute for Secure Boot.
 */
#include "efi_min.h"
#include "sha256.h"
#include "payload_contract.h"

typedef ES(EA *GET_INFO)(FILEP*,GUID*,UN*,void*);
typedef ES(EA *LOAD_IMAGE)(uint8_t,HANDLE,void*,void*,UN,HANDLE*);
typedef ES(EA *START_IMAGE)(HANDLE,UN*,C16**);
typedef ES(EA *INSTALL)(HANDLE*,GUID*,unsigned,void*);
typedef ES(EA *LOCATE_DP)(GUID*,void**,HANDLE*);
typedef ES(EA *WATCHDOG)(UN,uint64_t,UN,C16*);
typedef struct {
 HDR hdr;void *get_time,*set_time,*get_wakeup,*set_wakeup,*set_virtual,*convert;
 ES(EA *get_variable)(C16*,GUID*,uint32_t*,UN*,void*);
} RT_READ;
OFF(RT_READ,get_variable,0x48);
typedef struct LF2 LF2;
struct LF2 {ES(EA *load)(LF2*,uint8_t*,uint8_t,UN*,void*);};
static ST *st;
static uint8_t *initrd_data;
static int tcg;
static GUID li_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID dp_guid={0x9576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fi_guid={0x9576e92,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fsi_guid={0x9576e93,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID lf2_guid={0x4006c0c1,0xfcb3,0x403e,{0x99,0x6d,0x4a,0x6c,0x87,0x24,0xe0,0x6d}};
static GUID seed_guid={0x1ce1e5bc,0x7ceb,0x42f2,{0x81,0xe5,0x8a,0xad,0xf1,0x80,0xf5,0x7b}};
/* MEDIA_VENDOR_DP, Linux initrd GUID, END_ENTIRE_DP. */
static uint8_t initrd_dp[24]={4,3,20,0,0x27,0xe4,0x68,0x55,0xfc,0x68,0x3d,0x4f,0xac,0x74,0xca,0x55,0x52,0x31,0xcc,0x68,0x7f,0xff,4,0};
static C16 command_line[]=LC_CMDLINE;
void *memcpy(void*d,const void*s,size_t n){uint8_t*a=d;const uint8_t*b=s;while(n--)*a++=*b++;return d;}
void *memset(void*d,int c,size_t n){uint8_t*a=d;while(n--)*a++=(uint8_t)c;return d;}
static uint16_t u16(const uint8_t*p){return p[0]|((uint16_t)p[1]<<8);}
static uint64_t u64(const uint8_t*p){uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static void message(const char*s){C16 w[128];unsigned n=0;while(*s){if(tcg)__asm__ volatile("outb %0,%1"::"a"((uint8_t)*s),"Nd"((uint16_t)0x402));w[n++]=(uint8_t)*s++;if(n==127||!*s){w[n]=0;if(st&&st->out&&st->out->out)st->out->out(st->out,w);n=0;}}}
static void number(uint64_t v){char b[17];for(unsigned i=0;i<16;i++)b[i]="0123456789abcdef"[(v>>((15-i)*4))&15];b[16]=0;message(b);}
static __attribute__((noreturn)) void stop(const char*where,ES status){
 message("\r\nLC01_BOOT_STOP ");message(where);message(" status=0x");number(status);
 message("\r\nBoot has stopped. No fallback OS will be started.\r\nUse BMC power off; do not reset into an unintended OS.\r\n");
 /* No return, Exit(), ResetSystem(), file writes, or variable writes. The
  * firmware watchdog was disabled on entry; external BMC watchdogs are outside
  * this application's control. Each wait is bounded and uses no new resources. */
 for(;;){if(st&&st->bs&&st->bs->stall)st->bs->stall(100000);else __asm__ volatile("pause");}
}
static int ascii_equal(C16 a,C16 b){if(a>='a'&&a<='z')a-=32;if(b>='a'&&b<='z')b-=32;return a==b;}
static void require_seed_absent(const char*stage,int log_success){
 RT_READ*rt=st->rt;if(!rt||!rt->get_variable)stop("runtime_read_interface",ERR(3));
 UN n=0;ES e=rt->get_variable((C16*)L"RandomSeed",&seed_guid,0,&n,0);
 /* Never fetch the seed contents. Every result except exact absence stops. */
 if(e!=ERR(14)||n!=0)stop(stage,e==ERR(14)?ERR(33):e);
 if(log_success){message("LC01_RANDOMSEED_ABSENT ");message(stage);message("\r\n");}
}
static int file_path_is(const uint8_t*p,const C16*expected){
 if(!p||p[0]!=4||p[1]!=4)return 0;unsigned n=u16(p+2);if(n<6||n>512||(n&1))return 0;
 unsigned chars=(n-4)/2,i=0;for(;i<chars;i++){C16 c=u16(p+4+2*i);if(!ascii_equal(c,expected[i]))return 0;if(c==0){if(i!=chars-1)return 0;break;}}
 if(i==chars)return 0;return p[n]==0x7f&&p[n+1]==0xff&&u16(p+n+2)==4;
}
static void *make_path(const uint8_t*device,const C16*name){
 if(!device)stop("device_path_missing",ERR(2));UN p=0,chars=0;
 for(unsigned node=0;node<128;node++){
  if(p+4>4096)stop("device_path_bound",ERR(33));unsigned n=u16(device+p+2);
  if(n<4||n>4096-p)stop("device_path_length",ERR(33));
  if(device[p]==0x7f){if(device[p+1]!=0xff||n!=4)stop("device_path_end",ERR(33));break;}
  p+=n;if(node==127)stop("device_path_nodes",ERR(33));
 }
 while(name[chars]){if(chars>=250)stop("fixed_path_length",ERR(2));chars++;}UN fn=4+(chars+1)*2;
 uint8_t*path=0;ES e=st->bs->allocate_pool(2,p+fn+4,(void**)&path);if(e||!path)stop("path_allocation",e?e:ERR(9));
 memcpy(path,device,p);path[p]=4;path[p+1]=4;path[p+2]=(uint8_t)fn;path[p+3]=(uint8_t)(fn>>8);memcpy(path+p+4,name,(chars+1)*2);
 memcpy(path+p+fn,initrd_dp+20,4);return path;
}
static uint8_t *read_verified(FILEP*root,C16*name,UN expected,const uint8_t digest[32],const char*label){
 if(!expected||expected>64U*1024U*1024U)stop("compiled_size_bound",ERR(2));
 FILEP*f=0;ES e=root->open(root,&f,name,1,0);if(e||!f)stop(label,e?e:ERR(7));
 uint8_t info[1024];UN n=sizeof(info);e=((GET_INFO)f->get_info)(f,&fi_guid,&n,info);
 if(e||n<82||n>sizeof(info)||u64(info)!=n||u64(info+8)!=expected||(u64(info+72)&0x10)){f->close(f);stop("payload_length_or_info",e?e:ERR(33));}
 uint8_t*bytes=0;e=st->bs->allocate_pool(2,expected,(void**)&bytes);if(e||!bytes){f->close(f);stop("payload_allocation",e?e:ERR(9));}
 UN done=0;
 while(done<expected){UN want=expected-done;if(want>1024U*1024U)want=1024U*1024U;UN got=want;e=f->read(f,&got,bytes+done);if(e||got!=want){f->close(f);stop("payload_read_short_or_error",e?e:ERR(7));}done+=got;}
 uint8_t extra=0;n=1;e=f->read(f,&n,&extra);ES close_status=f->close(f);if(e||n||close_status)stop("payload_eof_or_close",e?e:(close_status?close_status:ERR(33)));
 uint8_t actual[32];ap_sha256(bytes,expected,actual);if(!ap_constant_equal(actual,digest,32))stop("payload_sha256",ERR(26));
 message("LC01_VERIFIED ");message(label);message("\r\n");return bytes;
}
static ES EA initrd_load(LF2*,uint8_t*,uint8_t,UN*,void*);
static LF2 initrd_protocol={initrd_load};
static ES EA initrd_load(LF2*self,uint8_t*path,uint8_t policy,UN*size,void*buffer){
 if(self!=&initrd_protocol||!path||!size)return ERR(2);if(policy)return ERR(3);
 if(path[0]!=0x7f||path[1]!=0xff||u16(path+2)!=4)return ERR(14);
 if(!initrd_data)return ERR(12);if(!buffer||*size<LC_INITRD_BYTES){*size=LC_INITRD_BYTES;return ERR(5);}
 memcpy(buffer,initrd_data,LC_INITRD_BYTES);*size=LC_INITRD_BYTES;message("LC01_INITRD_DELIVERED\r\n");return 0;
}
ES EA efi_main(HANDLE self,ST*table){
 st=table;uint32_t a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));tcg=b==0x54474354U&&c==0x43544743U&&d==0x47435447U;
 if(!st||!st->bs||!st->bs->set_watchdog)stop("system_table",ERR(2));ES e=((WATCHDOG)st->bs->set_watchdog)(0,0,0,0);if(e)stop("watchdog_disable",e);
 message("LC01_BOOTSTRAP_BEGIN\r\nFixed reviewed kernel and custom initramfs only.\r\n");
 require_seed_absent("seed_preflight",1);
 LOADED*li=0;e=st->bs->handle_protocol(self,&li_guid,(void**)&li);if(e||!li||!li->device)stop("loaded_image",e?e:ERR(2));
 if(!file_path_is(li->filepath,(C16*)L"\\EFI\\BOOT\\BOOTX64.EFI"))stop("bootstrap_file_path",ERR(33));
 FS*fs=0;FILEP*root=0;e=st->bs->handle_protocol(li->device,&fs_guid,(void**)&fs);if(e||!fs)stop("own_filesystem",e?e:ERR(7));e=fs->open_volume(fs,&root);if(e||!root)stop("own_volume",e?e:ERR(7));
 uint8_t fsi[512];UN size=sizeof(fsi);e=((GET_INFO)root->get_info)(root,&fsi_guid,&size,fsi);
 if(e||size<38||size>sizeof(fsi)||u64(fsi)!=size||fsi[8]>1){root->close(root);stop("volume_info_invalid",e?e:ERR(33));}
 message(fsi[8]?"LC01_BOOT_VOLUME_READONLY=1\r\n":"LC01_BOOT_VOLUME_READONLY=0 SOURCE_IMMUTABILITY_NOT_PROVEN\r\n");
 uint8_t*kernel=read_verified(root,(C16*)L"\\LINUX\\VMLINUX.EFI",LC_KERNEL_BYTES,lc_kernel_sha,"kernel");
 initrd_data=read_verified(root,(C16*)L"\\LINUX\\CAPACITY01.IMG",LC_INITRD_BYTES,lc_initrd_sha,"custom_initrd");e=root->close(root);if(e)stop("volume_close",e);
 void*device=0;e=st->bs->handle_protocol(li->device,&dp_guid,&device);if(e||!device)stop("own_device_path",e?e:ERR(7));void*kernel_path=make_path(device,(C16*)L"\\LINUX\\VMLINUX.EFI");
 void*remaining=initrd_dp;HANDLE collision=0;e=((LOCATE_DP)st->bs->locate_device_path)(&lf2_guid,&remaining,&collision);
 if(e!=ERR(14))stop("initrd_provider_collision_or_error",e?e:ERR(20));
 HANDLE provider=0;e=((INSTALL)st->bs->install_protocol)(&provider,&dp_guid,0,initrd_dp);if(e||!provider)stop("initrd_device_path_install",e?e:ERR(7));e=((INSTALL)st->bs->install_protocol)(&provider,&lf2_guid,0,&initrd_protocol);if(e)stop("initrd_protocol_install",e);
 HANDLE child=0;e=((LOAD_IMAGE)st->bs->load_image)(0,self,kernel_path,kernel,LC_KERNEL_BYTES,&child);if(e||!child)stop("kernel_LoadImage",e?e:ERR(1));
 LOADED*ki=0;e=st->bs->handle_protocol(child,&li_guid,(void**)&ki);if(e||!ki||ki->parent!=self||ki->device!=li->device||!file_path_is(ki->filepath,(C16*)L"\\LINUX\\VMLINUX.EFI"))stop("kernel_device_or_file_identity",e?e:ERR(33));
 ki->options=command_line;ki->options_size=sizeof(command_line);
 message("LC01_FIXED_CMDLINE ");message(LC_CMDLINE_ASCII);message("\r\nLC01_START_PINNED_KERNEL\r\n");
 require_seed_absent("seed_handoff",0);
 typedef UN(EA*RAISE)(UN);typedef void(EA*RESTORE)(UN);UN old_tpl=((RAISE)st->bs->raise_tpl)(31);((RESTORE)st->bs->restore_tpl)(old_tpl);uint64_t flags;__asm__ volatile("pushfq; popq %0":"=r"(flags));message("DEBUG_ONLY_TPL=");number(old_tpl);message(" FLAGS=");number(flags);message("\r\n");UN exit_size=0;C16*exit_data=0;e=((START_IMAGE)st->bs->start_image)(child,&exit_size,&exit_data);
 /* Even a returned EFI_SUCCESS is a failed diagnostic handoff. */
 stop("kernel_returned",e);
}
