/* VM-only test harness. Not part of P2 and not for use on physical machines.
 * Runs an UNCHANGED P2 file using real UEFI LoadImage/StartImage and reads
 * log bytes back through the real SimpleFileSystem protocol. */
#include "efi_min.h"
#include "probe_core.h"
static ST *st;
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID dp_guid={0x9576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static uint8_t data[65536];
void *memset(void *p,int c,size_t n){uint8_t *b=p;while(n--)*b++=(uint8_t)c;return p;}
void *memcpy(void *p,const void *s,size_t n){uint8_t *a=p;const uint8_t *b=s;while(n--)*a++=*b++;return p;}
static void debug_byte(char c){__asm__ volatile("outb %0, %1"::"a"((uint8_t)c),"Nd"((uint16_t)0x402));}
static void message(const char *s){
    C16 w[160];unsigned n=0;
    while(*s){debug_byte(*s);w[n++]=(uint8_t)*s++;
        if(n==159||!*s){w[n]=0;if(st->out&&st->out->out)st->out->out(st->out,w);n=0;}}
}
static void value(uint64_t x){char b[17];const char *h="0123456789ABCDEF";
    for(unsigned i=0;i<16;i++)b[i]=h[(x>>((15-i)*4))&15];b[16]=0;message(b);}
static int qemu_tcg(void){
    uint32_t a,b,c,d;
    __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(0x40000000),"c"(0));
    /* Hypervisor vendor TCGTCGTCGTCG; never touch QEMU I/O ports on a real board. */
    return b==0x54474354U&&c==0x43544743U&&d==0x47435447U;
}
static void finish(uint32_t code){
    message("VM_RUNNER_DONE\r\n");
    __asm__ volatile("outl %0, %1"::"a"(code),"Nd"((uint16_t)0xf4));
}
ES EA efi_main(HANDLE self,ST *table){
    st=table;
    if(!st||!st->bs||!qemu_tcg())return ERR(3);
    message("VM_RUNNER_BEGIN\r\n");
    LOADED *li=0;FS *fs=0;FILEP *root=0;uint8_t *device_path=0;
    ES e=st->bs->handle_protocol(self,&loaded_guid,(void **)&li);
    if(FAILED(e)||!li){finish(0x11);return ERR(7);}
    e=st->bs->handle_protocol(li->device,&fs_guid,(void **)&fs);
    if(FAILED(e)||!fs||FAILED(fs->open_volume(fs,&root))||!root){finish(0x12);return ERR(7);}
    unsigned repetitions=1;FILEP *cfg=0;
    e=root->open(root,&cfg,(C16 *)L"\\VMCASE.TXT",1,0);
    if(!FAILED(e)&&cfg){UN n=1;char ch=0;if(!FAILED(cfg->read(cfg,&n,&ch))&&n==1&&ch>='1'&&ch<='3')repetitions=(unsigned)(ch-'0');cfg->close(cfg);}
    e=st->bs->handle_protocol(li->device,&dp_guid,(void **)&device_path);
    if(FAILED(e)||!device_path){root->close(root);finish(0x13);return ERR(7);}
    size_t pos=0;
    while(pos+4<=1024){unsigned n=device_path[pos+2]|((unsigned)device_path[pos+3]<<8);
        if(n<4||n>1024-pos){root->close(root);finish(0x14);return ERR(7);}
        if(device_path[pos]==0x7f)break;pos+=n;}
    if(pos+4>1024){root->close(root);finish(0x15);return ERR(7);}
    C16 file_name[]=L"\\P2PROBE.EFI";size_t file_node_size=4+sizeof(file_name);
    uint8_t *path=0;e=st->bs->allocate_pool(4,pos+file_node_size+4,(void **)&path);
    if(FAILED(e)||!path){root->close(root);finish(0x16);return ERR(9);}
    memcpy(path,device_path,pos);path[pos]=4;path[pos+1]=4;
    path[pos+2]=(uint8_t)file_node_size;path[pos+3]=(uint8_t)(file_node_size>>8);
    memcpy(path+pos+4,file_name,sizeof(file_name));
    uint8_t end[]={0x7f,0xff,4,0};memcpy(path+pos+file_node_size,end,4);
    typedef ES (EA *LOAD)(uint8_t,HANDLE,void *,void *,UN,HANDLE *);
    typedef ES (EA *START)(HANDLE,UN *,C16 **);
    for(unsigned i=0;i<repetitions;i++){
        HANDLE child=0;e=((LOAD)st->bs->load_image)(0,self,path,0,0,&child);
        message("VM_LOAD_STATUS=");value(e);message("\r\n");
        if(!FAILED(e)&&child){UN exit_size=0;C16 *exit_data=0;
            e=((START)st->bs->start_image)(child,&exit_size,&exit_data);
            message("VM_PROBE_RETURN=");value(e);message("\r\n");
            if(exit_data)st->bs->free_pool(exit_data);
            /* Returning EFI applications are unloaded by StartImage's Exit path. */
        }
    }
    st->bs->free_pool(path);
    for(unsigned i=0;i<10;i++){
        C16 name[]=L"\\AITWK-000.TXT";name[9]=(C16)('0'+i);FILEP *file=0;
        e=root->open(root,&file,name,1,0);
        if(FAILED(e)||!file)continue;
        UN size=sizeof(data);e=file->read(file,&size,data);file->close(file);
        message("VM_READBACK_INDEX=");value(i);message(" STATUS=");value(e);
        message(" SIZE=");value(size);message(" CRC32=");
        value(!FAILED(e)&&size<=sizeof(data)?probe_crc32(data,(size_t)size):0);message("\r\n");
    }
    root->close(root);finish(0x10);return 0;
}
