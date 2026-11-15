/* Custom RAM init. No shell, exec, sockets, automount, block-device access,
 * USB raw transfer, SCSI write/reset, firmware-variable or SPI operation. */
#define _GNU_SOURCE
#include "core.h"
#include "modules.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <scsi/sg.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
_Static_assert(sizeof(sg_io_hdr_t)==88,"sg v3 x64 ABI");
_Static_assert(offsetof(sg_io_hdr_t,dxferp)==16&&offsetof(sg_io_hdr_t,status)==64&&offsetof(sg_io_hdr_t,resid)==72,"sg offsets");
static unsigned stage,devices,interfaces,sgcount,commands,checks,loaded,dmi_match;
static int failure,error_number,pending;static char target[64],sgname[32],sgpath[PATH_MAX],interface_path[PATH_MAX];
static void emit(void);
static sg_io_hdr_t response;static uint8_t data_guard[40],sense_guard[64],cdb_guard[42];static int valid,guards;
typedef struct {int ret,err,guard;sg_io_hdr_t packet;uint8_t data[8],sense[32];} OUTCOME;
static OUTCOME attempts[2];
static uint32_t last_lba,block_bytes;static char cmdline[4096];
static int exact_line_file(const char *path,const char *expected){
 char b[128];int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
 ssize_t n=read(fd,b,sizeof(b)),more;char extra;more=n>=0?read(fd,&extra,1):-1;int saved=errno;close(fd);errno=saved;
 return n>=0&&more==0&&lc_exact_line(b,(size_t)n,expected)?0:-1;
}
static int text(const char *path,char *buf,size_t cap){
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;ssize_t n=read(fd,buf,cap-1);char extra;ssize_t more=n>=0?read(fd,&extra,1):-1;int saved=errno;close(fd);errno=saved;
 if(n<0||more!=0||memchr(buf,0,(size_t)n)){errno=EOVERFLOW;return -1;}buf[n]=0;while(n>0&&(buf[n-1]=='\n'||buf[n-1]=='\r'||buf[n-1]==' '||buf[n-1]=='\t'))buf[--n]=0;return 0;
}
static int attr(const char *base,const char *name,char *out,size_t n){char p[PATH_MAX];int k=snprintf(p,sizeof(p),"%s/%s",base,name);return k>0&&(size_t)k<sizeof(p)?text(p,out,n):-1;}
static int number(const char *base,const char *name,unsigned *out){char b[64],*end;if(attr(base,name,b,sizeof(b)))return -1;errno=0;unsigned long v=strtoul(b,&end,16);if(errno||end==b||*end||v>0xffffffffUL)return -1;*out=(unsigned)v;return 0;}
static int write_control(const char *path,const char *value){int fd=open(path,O_WRONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;size_t n=strlen(value);ssize_t k=write(fd,value,n);int e=errno;int c=close(fd);errno=e;return k==(ssize_t)n&&c==0?0:-1;}
static int off(const char *path){char b[32];return write_control(path,"0\n")||text(path,b,sizeof(b))||strcmp(b,"0");}
static int exists(const char *path){struct stat st;int r=lstat(path,&st);return r==0?1:errno==ENOENT?0:-1;}
static int unbound(const char *path){char p[PATH_MAX];snprintf(p,sizeof(p),"%s/driver",path);return exists(p)==0;}
static int token(const char *wanted){size_t n=strlen(wanted);const char *p=cmdline;unsigned count=0;while(*p){while(*p==' ')p++;const char *q=strchr(p,' ');size_t z=q?(size_t)(q-p):strlen(p);if(z==n&&!memcmp(p,wanted,n))count++;if(!q)break;p=q+1;}return count==1;}
static int msleep(unsigned ms){struct timespec t={ms/1000,(long)(ms%1000)*1000000L};return nanosleep(&t,0);}
static int safe_name(const char *s){size_t n=strlen(s);if(!n||n>=63)return 0;for(size_t i=0;i<n;i++)if(!((s[i]>='0'&&s[i]<='9')||s[i]=='-'||s[i]=='.'||s[i]==':'))return 0;return 1;}
static int system_devices(void){
 const char *dirs[]={"/sys/class/block","/sys/class/net"};
 for(unsigned d=0;d<2;d++){
  DIR *dir=opendir(dirs[d]);if(!dir)return -1;struct dirent *e;unsigned n=0;int ok=1;
  while((e=readdir(dir))){if(e->d_name[0]=='.')continue;if(++n>128){ok=0;break;}
   if(d==1){if(strcmp(e->d_name,"lo")){ok=0;break;}}
   else {const char *s=e->d_name;if(strncmp(s,"ram",3)||!s[3]){ok=0;break;}for(s+=3;*s;s++)if(*s<'0'||*s>'9')ok=0;}
  }closedir(dir);if(!ok)return -1;
 }return 0;
}
static int module_inventory(unsigned expected){
 char b[16384];if(text("/proc/modules",b,sizeof(b)))return -1;unsigned seen=0;char *save=0;
 for(char *line=strtok_r(b,"\n",&save);line;line=strtok_r(0,"\n",&save)){
  char *end=strchr(line,' ');if(!end)return -1;*end=0;unsigned i=0;while(i<expected&&strcmp(line,module_list[i].name))i++;if(i==expected||(seen&(1u<<i)))return -1;seen|=1u<<i;
 }return seen==((1u<<expected)-1)?0:-1;
}
static int load_module(unsigned i){
 char path[128];snprintf(path,sizeof(path),"/modules/%s",module_list[i].file);int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
 struct stat st;int r=fstat(fd,&st);if(r||!S_ISREG(st.st_mode)||(uint64_t)st.st_size!=module_list[i].bytes){close(fd);return -1;}
 r=(int)syscall(SYS_finit_module,fd,module_list[i].params,0);int e=errno;close(fd);errno=e;if(r)return -1;loaded=i+1;return module_inventory(loaded);
}
static int locate_target(void){
 DIR *dir=opendir("/sys/bus/usb/devices");if(!dir)return -1;struct dirent *e;unsigned entries=0;devices=interfaces=0;target[0]=0;interface_path[0]=0;
 while((e=readdir(dir))){
  if(e->d_name[0]=='.')continue;if(++entries>128){closedir(dir);return -1;}
  if(strchr(e->d_name,':')||!safe_name(e->d_name))continue;
  char base[PATH_MAX];snprintf(base,sizeof(base),"/sys/bus/usb/devices/%s",e->d_name);unsigned vid,pid;
  if(number(base,"idVendor",&vid)||number(base,"idProduct",&pid)){closedir(dir);return -1;}
  if(vid!=LC_USB_VID||pid!=LC_USB_PID)continue;devices++;
  DIR *sub=opendir(base);if(!sub){closedir(dir);return -1;}struct dirent *f;
  while((f=readdir(sub))){if(!strchr(f->d_name,':')||!safe_name(f->d_name))continue;
   char iface[PATH_MAX];int k=snprintf(iface,sizeof(iface),"%s/%s",base,f->d_name);if(k<0||(size_t)k>=sizeof(iface)){closedir(sub);closedir(dir);return -1;}
   unsigned no,alt,eps,cls,sc,pr;
   if(number(iface,"bInterfaceNumber",&no)||number(iface,"bAlternateSetting",&alt)||number(iface,"bNumEndpoints",&eps)||number(iface,"bInterfaceClass",&cls)||number(iface,"bInterfaceSubClass",&sc)||number(iface,"bInterfaceProtocol",&pr)){closedir(sub);closedir(dir);return -1;}
   if(!lc_identity(vid,pid,no,alt,eps,cls,sc,pr))continue;
   interfaces++;snprintf(target,sizeof(target),"%s",f->d_name);
   if(!realpath(iface,interface_path)||strncmp(interface_path,"/sys/devices/",13)||!strstr(interface_path,"/0000:00:14.0/")){closedir(sub);closedir(dir);return -1;}
  }closedir(sub);
 }closedir(dir);return 0;
}
static int find_sg(void){
 DIR *dir=opendir("/sys/class/scsi_generic");if(!dir)return errno==ENOENT?0:-1;struct dirent *e;unsigned entries=0;sgcount=0;
 while((e=readdir(dir))){if(e->d_name[0]=='.')continue;if(++entries>128){closedir(dir);return -1;}
  if(strncmp(e->d_name,"sg",2)||!e->d_name[2]||strlen(e->d_name)>=sizeof(sgname)){closedir(dir);return -1;}for(const char *q=e->d_name+2;*q;q++)if(*q<'0'||*q>'9'){closedir(dir);return -1;}
  char path[PATH_MAX],resolved[PATH_MAX];snprintf(path,sizeof(path),"/sys/class/scsi_generic/%s/device",e->d_name);
  if(!realpath(path,resolved)){closedir(dir);return -1;}size_t n=strlen(interface_path);
  if(strncmp(resolved,interface_path,n)||resolved[n]!='/'){closedir(dir);return -1;}
  sgcount++;snprintf(sgname,sizeof(sgname),"%s",e->d_name);snprintf(sgpath,sizeof(sgpath),"%s",resolved);
 }closedir(dir);return 0;
}
static void perform(int fd,unsigned index){
 memset(data_guard,0xa5,sizeof(data_guard));memset(sense_guard,0x5a,sizeof(sense_guard));memset(cdb_guard,0x3c,sizeof(cdb_guard));
 uint8_t *data=data_guard+16,*sense=sense_guard+16,*cdb=cdb_guard+16;memset(data,0,8);memset(sense,0,32);memset(cdb,0,10);cdb[0]=0x25;
 memset(&response,0,sizeof(response));response.interface_id='S';response.dxfer_direction=SG_DXFER_FROM_DEV;response.cmd_len=10;response.mx_sb_len=32;response.dxfer_len=8;response.dxferp=data;response.cmdp=cdb;response.sbp=sense;response.timeout=2000;
 OUTCOME *out=&attempts[index];commands=index+1;errno=0;out->ret=ioctl(fd,SG_IO,&response);out->err=errno;error_number=errno;
 guards=1;for(unsigned i=0;i<40;i++)if((i<16||i>=24)&&data_guard[i]!=0xa5)guards=0;
 for(unsigned i=0;i<64;i++)if((i<16||i>=48)&&sense_guard[i]!=0x5a)guards=0;
 for(unsigned i=0;i<42;i++)if((i<16||i>=26)&&cdb_guard[i]!=0x3c)guards=0;
 for(unsigned i=0;i<10;i++)if(cdb[i]!=(i?0:0x25))guards=0;
 if(response.interface_id!='S'||response.dxfer_direction!=SG_DXFER_FROM_DEV||response.cmd_len!=10||response.mx_sb_len!=32||response.iovec_count||response.dxfer_len!=8||response.dxferp!=data||response.cmdp!=cdb||response.sbp!=sense||response.timeout!=2000||response.flags||response.pack_id||response.usr_ptr)guards=0;
 out->packet=response;out->guard=guards;memcpy(out->data,data,8);memcpy(out->sense,sense,32);
}
static int submit(void){
 char selected[64],selected_path[PATH_MAX];snprintf(selected,sizeof(selected),"%s",target);snprintf(selected_path,sizeof(selected_path),"%s",interface_path);
 if(locate_target()||devices!=1||interfaces!=1||strcmp(target,selected)||strcmp(interface_path,selected_path))return -1;
 char path[128],attrpath[128],devnum[64];snprintf(path,sizeof(path),"/dev/%s",sgname);snprintf(attrpath,sizeof(attrpath),"/sys/class/scsi_generic/%s/dev",sgname);
 if(text(attrpath,devnum,sizeof(devnum)))return -1;unsigned ma,mi;char extra;if(sscanf(devnum,"%u:%u%c",&ma,&mi,&extra)!=2||ma!=21)return -1;
 int fd=open(path,O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;struct stat st;
 if(fstat(fd,&st)||!S_ISCHR(st.st_mode)||major(st.st_rdev)!=ma||minor(st.st_rdev)!=mi){close(fd);return -1;}
 struct sg_scsi_id id;memset(&id,0xff,sizeof(id));int version=0;
 if(ioctl(fd,SG_GET_VERSION_NUM,&version)||version<30000||ioctl(fd,SG_GET_SCSI_ID,&id)||id.scsi_type!=0||id.host_no<0||id.channel!=0||id.scsi_id!=0||id.lun!=0){close(fd);return -1;}
 char expected[64];snprintf(expected,sizeof(expected),"/%d:0:0:0",id.host_no);size_t a=strlen(sgpath),b=strlen(expected);if(a<b||strcmp(sgpath+a-b,expected)){close(fd);return -1;}
 checks|=128;pending=1;emit();pending=0;perform(fd,0);
 OUTCOME *first=&attempts[0];sg_io_hdr_t *p=&first->packet;
 if(lc_retry_ua(first->ret,p->status,p->masked_status,p->msg_status,p->host_status,p->driver_status,p->resid,p->info,first->guard,first->data,first->sense,p->sb_len_wr))perform(fd,1);
 close(fd);OUTCOME *out=&attempts[commands-1];p=&out->packet;
 valid=lc_response(out->ret,p->status,p->masked_status,p->msg_status,p->host_status,p->driver_status,p->sb_len_wr,p->resid,p->info,out->guard)&&lc_capacity(out->data,&last_lba,&block_bytes);
 return valid?0:-1;
}
static int run(void){
 stage=1;struct utsname u;if(getpid()!=1||uname(&u)||strcmp(u.release,"6.12.114-0-lts"))return -1;
 if(mount("proc","/proc","proc",MS_NOSUID|MS_NODEV|MS_NOEXEC,0)||mount("sysfs","/sys","sysfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,0)||mount("devtmpfs","/dev","devtmpfs",MS_NOSUID|MS_NOEXEC,0))return -1;
 stage=2;if(text("/proc/cmdline",cmdline,sizeof(cmdline)))return -1;
 const char *required[]={"rdinit=/init","efi=noruntime","noresume","erst_disable","pstore.backend=lc01_none","initcall_blacklist=mei_me_driver_init,xlblk_init,netif_init","ipv6.disable=1","panic=0"};
 for(unsigned i=0;i<sizeof(required)/sizeof(required[0]);i++)if(!token(required[i]))return -1;
 char b[128];if(text("/sys/module/pstore/parameters/backend",b,sizeof(b))||strcmp(b,"lc01_none")||exists("/sys/bus/pci/drivers/mei_me")!=0||exists("/sys/bus/xen/drivers/vbd")!=0)return -1;checks|=1;
 if(write_control("/proc/sys/kernel/hotplug","\n")||text("/proc/sys/kernel/hotplug",b,sizeof(b))||*b||write_control("/proc/sys/kernel/modprobe","\n")||text("/proc/sys/kernel/modprobe",b,sizeof(b))||*b||write_control("/proc/sys/kernel/printk","0 0 0 0\n"))return -1;
 stage=3;
 if(exact_line_file("/sys/class/dmi/id/board_name","Pro WS W790E-SAGE SE")||exact_line_file("/sys/class/dmi/id/bios_version","1904"))return -1;
 dmi_match=1;checks|=256;
 if(system_devices()||module_inventory(0))return -1;checks|=2;
 const char *pci="/sys/bus/pci/devices/0000:00:14.0";unsigned vendor,cls;
 if(number(pci,"vendor",&vendor)||number(pci,"class",&cls)||vendor!=LC_PCI_VID||cls!=0x0c0330||!unbound(pci)||off("/sys/bus/pci/drivers_autoprobe"))return -1;checks|=4;
 stage=4;for(unsigned i=0;i<4;i++)if(load_module(i))return -1;
 if(write_control("/sys/bus/pci/drivers/xhci_hcd/bind","0000:00:14.0\n"))return -1;
 stage=5;unsigned stable=0;char previous[64]={0};
 for(unsigned i=0;i<150;i++){
  if(locate_target())return -1;if(devices>1||interfaces>1)return -1;
  if(devices==1&&interfaces==1&&!strcmp(previous,target))stable++;else stable=0;
  /* Do not stop after the first device settles: subsequent ports may still
   * be enumerating. Use the entire bounded observation window. */
  snprintf(previous,sizeof(previous),"%s",target);msleep(100);
 }
 if(devices!=1||interfaces!=1||stable<5||!unbound(interface_path))return -1;checks|=8;
 stage=6;if(off("/sys/bus/usb/drivers_autoprobe"))return -1;
 for(unsigned i=4;i<8;i++)if(load_module(i))return -1;
 char selected[64];snprintf(selected,sizeof(selected),"%s",target);
 if(locate_target()||devices!=1||interfaces!=1||strcmp(selected,target)||!unbound(interface_path))return -1;
 if(write_control("/sys/bus/usb/drivers/usb-storage/bind",target))return -1;checks|=16;
 stage=7;for(unsigned i=0;i<100;i++){if(find_sg())return -1;if(sgcount>1)return -1;if(sgcount==1)break;msleep(100);}if(sgcount!=1)return -1;
 if(system_devices()||module_inventory(8)||text("/sys/bus/usb/drivers_autoprobe",b,sizeof(b))||strcmp(b,"0")||text("/sys/bus/pci/drivers_autoprobe",b,sizeof(b))||strcmp(b,"0"))return -1;checks|=32;
 if(write_control("/proc/sys/kernel/modules_disabled","1\n")||text("/proc/sys/kernel/modules_disabled",b,sizeof(b))||strcmp(b,"1"))return -1;checks|=64;
 stage=8;return submit();
}
static void emit(void){
 char packets[2][200];
 for(unsigned j=0;j<2;j++){
  if(j>=commands){snprintf(packets[j],sizeof(packets[j]),"NONE");continue;}
  OUTCOME *out=&attempts[j];sg_io_hdr_t *p=&out->packet;char data[17]={0},sense[65]={0};
  for(unsigned i=0;i<8;i++)snprintf(data+i*2,3,"%02X",out->data[i]);unsigned n=p->sb_len_wr;if(n>32)n=32;for(unsigned i=0;i<n;i++)snprintf(sense+i*2,3,"%02X",out->sense[i]);
  /* Fixed fields documented by decode_linux_log.py: ret,errno,status,masked,
   * msg,host,driver,resid,info,sense_len,guard,data8,sense. No silent truncation. */
  int z=snprintf(packets[j],sizeof(packets[j]),"%d,%d,%02X,%02X,%02X,%04X,%04X,%d,%08X,%u,%d,%s,%s",out->ret,out->err,p->status,p->masked_status,p->msg_status,p->host_status,p->driver_status,p->resid,p->info,p->sb_len_wr,out->guard,data,sense);
  if(z<0||(size_t)z>=sizeof(packets[j]))snprintf(packets[j],sizeof(packets[j]),"PACKET_OVERFLOW");
 }
 char log[769];int k=snprintf(log,sizeof(log),
  "LINUX-CAPACITY-01 %s\r\nKERNEL=6.12.114-0-lts\r\nEXPECTED_BOARD=Pro WS W790E-SAGE SE BIOS=1904 DMI_MATCH=%u\r\nSTAGE=%u ERROR=%d ERRNO=%d CHECKS=%03X\r\nUSB=%04X:%04X DEVICES=%u INTERFACES=%u\r\nTARGET=%s SG=%s COUNT=%u MODULES=%u\r\nSG_IO_CALLS=%u CDB=25000000000000000000 TIMEOUT_MS=2000\r\nA1=%s\r\nA2=%s\r\nVALID=%d LAST_LBA=%08X BLOCK_BYTES=%08X\r\nPROBE_BLOCK_READS=0 PROBE_STORAGE_WRITES=0 PROBE_RESETS=0\r\nKERNEL_SCAN_RECOVERY_MAY_ISSUE_COMMANDS\r\nRESULT=%s\r\n%s\r\n",
  LC_VARIANT,dmi_match,stage,failure,error_number,checks,LC_USB_VID,LC_USB_PID,devices,interfaces,target,sgname,sgcount,loaded,commands,packets[0],packets[1],valid,last_lba,block_bytes,pending?"PENDING":valid&&!failure?"CAPACITY_OBSERVED":"REFUSED_OR_FAILED",pending?"PROBE_PENDING":"PROBE_COMPLETE");
 if(k<0||(size_t)k>=sizeof(log)){snprintf(log,sizeof(log),"LINUX-CAPACITY-01 %s\r\nRESULT=LOG_OVERFLOW\r\nPROBE_COMPLETE\r\n",LC_VARIANT);k=(int)strlen(log);}
 char envelope[900];int m=snprintf(envelope,sizeof(envelope),"\033[2J\033[H\033[?25lLC01_LOG_BEGIN\r\n%.*sLC01_LOG_END BYTES=%d CRC=%08X\r\n",k,log,k,lc_crc32(log,(size_t)k));
 int fd=open("/dev/tty0",O_WRONLY|O_CLOEXEC|O_NOFOLLOW);if(fd>=0){write(fd,envelope,(size_t)m);close(fd);}if(strstr(cmdline,"console=ttyS0"))write(1,envelope,(size_t)m);
 lc_display(log,(size_t)k,pending?"PENDING":valid&&!failure?"CAPACITY OBSERVED":"REFUSED OR FAILED");
}
int main(void){failure=run();if(failure&&commands==0)error_number=errno;emit();for(;;)pause();}
