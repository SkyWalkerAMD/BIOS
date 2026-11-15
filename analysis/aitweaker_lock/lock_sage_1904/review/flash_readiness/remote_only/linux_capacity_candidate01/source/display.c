/* Framebuffer display only: validate packed RGB32 layout before mmap/write.
 * No mode change, hardware address access, disk access or input driver. */
#define _GNU_SOURCE
#include "core.h"
#include "vendor/qrcodegen.h"
#include "font.h"
#include <fcntl.h>
#include <linux/fb.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
static uint8_t qr[qrcodegen_BUFFER_LEN_FOR_VERSION(30)],temp[qrcodegen_BUFFER_LEN_FOR_VERSION(30)];
static uint8_t *memory;static unsigned width,height,stride,xoff,yoff;
static void pixel(unsigned x,unsigned y,uint32_t color){if(x<width&&y<height)*(uint32_t *)(memory+(size_t)(y+yoff)*stride+(size_t)(x+xoff)*4)=color;}
static void label(unsigned x,unsigned y,const char *s,unsigned scale){
 for(;*s;s++,x+=6*scale){unsigned ch=(uint8_t)*s;if(ch>='a'&&ch<='z')ch-=32;
 const uint8_t *rows=ch>='0'&&ch<='9'?font[ch-'0']:(ch>='A'&&ch<='Z'?font[ch-'A'+10]:0);
 for(unsigned j=0;j<7;j++){unsigned bits=rows?rows[j]:0;if(ch=='-'&&j==3)bits=31;if(ch==':'&&(j==2||j==5))bits=4;
 for(unsigned i=0;i<5;i++)if(bits&(1u<<(4-i)))for(unsigned dy=0;dy<scale;dy++)for(unsigned dx=0;dx<scale;dx++)pixel(x+i*scale+dx,y+j*scale+dy,0);}}
}
int lc_display(const char *log,size_t n,const char *phase){
 size_t len=lc_frame(log,n,temp,sizeof(temp));if(!len)return -1;
 if(!qrcodegen_encodeBinary(temp,len,qr,qrcodegen_Ecc_MEDIUM,1,30,qrcodegen_Mask_AUTO,true))return -1;
 int fd=open("/dev/fb0",O_RDWR|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;struct stat st;struct fb_var_screeninfo v;struct fb_fix_screeninfo f;
 memset(&v,0,sizeof(v));memset(&f,0,sizeof(f));
 if(fstat(fd,&st)||!S_ISCHR(st.st_mode)||ioctl(fd,FBIOGET_VSCREENINFO,&v)||ioctl(fd,FBIOGET_FSCREENINFO,&f)){close(fd);return -1;}
 unsigned side=(unsigned)qrcodegen_getSize(qr)+8;
 if(f.type!=FB_TYPE_PACKED_PIXELS||f.visual!=FB_VISUAL_TRUECOLOR||v.bits_per_pixel!=32||v.red.length!=8||v.green.length!=8||v.blue.length!=8||v.red.msb_right||v.green.msb_right||v.blue.msb_right||v.green.offset!=8||!((v.red.offset==16&&v.blue.offset==0)||(v.red.offset==0&&v.blue.offset==16))||v.transp.length>8||v.xres<640||v.yres<480||v.xres>4096||v.yres>2160||v.xres_virtual<v.xres||v.yres_virtual<v.yres||v.xoffset>v.xres_virtual-v.xres||v.yoffset>v.yres_virtual-v.yres||f.line_length%4||f.line_length<(uint64_t)v.xres_virtual*4||f.smem_len>64*1024*1024||(uint64_t)(v.yoffset+v.yres)*f.line_length>f.smem_len){close(fd);return -1;}
 unsigned scale=(v.yres-130)/side;if(scale>(v.xres-40)/side)scale=(v.xres-40)/side;if(scale>6)scale=6;if(scale<2){close(fd);return -1;}
 memory=mmap(0,f.smem_len,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);if(memory==MAP_FAILED){close(fd);memory=0;return -1;}
 width=v.xres;height=v.yres;stride=f.line_length;xoff=v.xoffset;yoff=v.yoffset;
 for(unsigned y=0;y<height;y++)for(unsigned x=0;x<width;x++)pixel(x,y,0x00ffffff);
 label(20,14,"LINUX CAPACITY 01",2);char title[80];snprintf(title,sizeof(title),"ONE QR PAGE  BYTES %u CRC %08X",(unsigned)n,lc_crc32(log,n));label(20,40,title,2);label(20,64,phase,1);
 unsigned left=(width-side*scale)/2,top=83;
 for(unsigned y=0;y<side-8;y++)for(unsigned x=0;x<side-8;x++)if(qrcodegen_getModule(qr,(int)x,(int)y))
  for(unsigned dy=0;dy<scale;dy++)for(unsigned dx=0;dx<scale;dx++)pixel(left+(x+4)*scale+dx,top+(y+4)*scale+dy,0);
 label(20,height-35,"SAVE THIS SCREEN  NO KEYBOARD REQUIRED",2);
 munmap(memory,f.smem_len);memory=0;close(fd);return 0;
}
