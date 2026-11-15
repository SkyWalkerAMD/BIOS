#include "source/snp_stage.c"
ST *gST;REPORT report;char audit[131072];UN audit_len;
static ST st;static BS bs;static RT rt;static FILEP root,file;static DB db;static NII nii;
static HANDLE hs[3]={(HANDLE)3,(HANDLE)4,(HANDLE)5};
static uint8_t up[]={3,5,6,0,9,0,0x7f,0xff,4,0},np[47];
static uint8_t pool[40000];static unsigned pool_at;
static int checks,failure,good,usb,ncount,existing,old,flag,bad_size,bad_crc,bad_db,reads,loads,starts,supports,binds,pub;
static ES var_status,open_status,load_status,start_status,support_status,bind_status;
#define CK(x) do{checks++;if(!(x)&&!failure)failure=__LINE__;}while(0)
void *memcpy(void *d,const void *s,size_t n){uint8_t *x=d;const uint8_t *y=s;while(n--)*x++=*y++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *x=d;while(n--)*x++=(uint8_t)c;return d;}
int eq(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
uint16_t u16(const uint8_t *s){return s[0]|(uint16_t)s[1]<<8;}
void logtext(const char *s){(void)s;}void logbytes(const uint8_t *p,size_t n){(void)p;(void)n;}void status(const char *s,ES e){(void)s;(void)e;}
int i3_target_valid(void){return good;}
int usb_target_handles(HANDLE out[2]){out[0]=(HANDLE)1;out[1]=(HANDLE)2;return good&&usb;}
uint32_t probe_crc32(const void *p,size_t n){(void)p;CK(n==I3A_SNP_BYTES);return bad_crc?0:I3A_SNP_CRC32;}
static ES EA handles(uint32_t type,GUID *g,void *key,UN *n,HANDLE **h){(void)type;(void)key;*h=0;*n=0;if(!eq(g,&nii31,16)||!ncount)return ERR(14);*h=hs;*n=ncount;return 0;}
static ES EA handle(HANDLE h,GUID *g,void **p){
 *p=0;if(eq(g,&dp,16))*p=h==(HANDLE)1?up:np;
 else if(eq(g,&nii31,16))*p=&nii;
 else if(eq(g,&snp,16)){if(existing||pub)*p=&db;}
 else if(eq(g,&binding_guid,16)){CK(h==(HANDLE)6);*p=&db;}
 return *p?0:ERR(3);
}
static ES EA locate(GUID *g,void *key,void **p){(void)key;*p=0;if(eq(g,&marker_guid,16)&&old){*p=pool;return 0;}return ERR(14);}
static ES EA alloc(uint32_t type,UN n,void **p){CK(type==4&&n<30000&&pool_at+n<=sizeof(pool));*p=pool+pool_at;pool_at+=(unsigned)n+16;return 0;}
static ES EA freep(void *p){(void)p;return 0;}
static ES EA getvar(C16 *name,GUID *g,uint32_t *attr,UN *size,void *out){CK(eq(name,W("NetworkStackVar"),32)&&eq(g,&nsvar,16)&&*size==8);reads++;*size=bad_size?7:8;*attr=3;memset(out,0,8);*(uint8_t *)out=(uint8_t)flag;return var_status;}
static ES EA openf(FILEP *f,FILEP **p,C16 *name,uint64_t mode,uint64_t attr){CK(f==&root&&eq(name,W("\\EFI\\BOOT\\I3ASNP.EFI"),sizeof(L"\\EFI\\BOOT\\I3ASNP.EFI"))&&mode==1&&!attr);*p=&file;return open_status;}
static ES EA readf(FILEP *f,UN *n,void *p){CK(f==&file&&*n==I3A_SNP_BYTES+1);*n=I3A_SNP_BYTES;memset(p,0,(size_t)*n);return 0;}
static ES EA closef(FILEP *f){CK(f==&file);return 0;}
static ES EA install(HANDLE *h,GUID *g,uint32_t type,void *p){CK(eq(g,&marker_guid,16)&&!type&&((MARKER *)p)->controller==(HANDLE)3);*h=(HANDLE)9;old=1;return 0;}
static ES EA load(uint8_t policy,HANDLE parent,void *path,void *data,UN size,HANDLE *h){CK(!policy&&parent==(HANDLE)8&&!path&&data&&size==I3A_SNP_BYTES);loads++;*h=(HANDLE)6;return load_status;}
static ES EA start(HANDLE h,UN *size,C16 **exit){CK(h==(HANDLE)6&&!size&&!exit);starts++;return start_status;}
static ES EA supported(DB *d,HANDLE h,void *path){CK(d==&db&&h==(HANDLE)3&&!path);supports++;return support_status;}
static ES EA bind(DB *d,HANDLE h,void *path){CK(d==&db&&h==(HANDLE)3&&!path);binds++;if(!bind_status)pub=1;return bind_status;}
static void reset(void){
 memset(&st,0,sizeof(st));memset(&bs,0,sizeof(bs));memset(&rt,0,sizeof(rt));memset(&root,0,sizeof(root));memset(&file,0,sizeof(file));memset(&db,0,sizeof(db));memset(&nii,0,sizeof(nii));
 good=usb=ncount=1;existing=old=flag=bad_size=bad_crc=bad_db=reads=loads=starts=supports=binds=pub=0;pool_at=0;var_status=open_status=load_status=start_status=support_status=bind_status=0;
 memcpy(np,up,6);np[6]=3;np[7]=11;np[8]=37;np[9]=0;memset(np+10,0,33);memcpy(np+43,up+6,4);
 nii.revision=0x20000;nii.type=1;nii.major=3;nii.minor=1;memcpy(nii.tag,"UNDI",4);
 st.bs=&bs;st.rt=&rt;gST=&st;bs.locate_handles=handles;bs.handle_protocol=handle;bs.locate_protocol=locate;bs.allocate_pool=alloc;bs.free_pool=freep;bs.install_protocol=install;bs.load_image=load;bs.start_image=start;rt.get_variable=getvar;
 root.open=openf;file.read=readf;file.close=closef;db.image=db.binding=(HANDLE)6;db.supported=supported;db.start=bind;
}
int run_tests(void){
 reset();CK(snp_stage_load((HANDLE)8,&root)==0&&loads==1&&starts==1&&supports==1&&binds==1&&pub);CK(snp_stage_load((HANDLE)8,&root)==ERR(20)&&loads==1);
 reset();good=0;CK(snp_stage_load((HANDLE)8,&root)==ERR(15)&&!loads&&!reads);
 reset();CK(snp_stage_load((HANDLE)8,0)==ERR(15)&&!loads);
 reset();usb=0;CK(snp_stage_load((HANDLE)8,&root)==ERR(15)&&!loads);
 reset();ncount=0;CK(snp_stage_load((HANDLE)8,&root)==ERR(15)&&!loads);
 reset();ncount=2;CK(snp_stage_load((HANDLE)8,&root)==ERR(15)&&!loads);
 reset();np[4]^=1;CK(snp_stage_load((HANDLE)8,&root)==ERR(15)&&!loads);
 reset();np[8]=36;CK(snp_stage_load((HANDLE)8,&root)==ERR(15)&&!loads);
 reset();nii.type=2;CK(snp_stage_load((HANDLE)8,&root)==ERR(15)&&!loads);
 reset();nii.tag[0]='X';CK(snp_stage_load((HANDLE)8,&root)==ERR(15)&&!loads);
 reset();nii.minor=0;CK(snp_stage_load((HANDLE)8,&root)==ERR(15)&&!loads);
 reset();existing=1;CK(snp_stage_load((HANDLE)8,&root)==ERR(20)&&!loads&&!reads);
 reset();old=1;CK(snp_stage_load((HANDLE)8,&root)==ERR(20)&&!loads);
 reset();var_status=ERR(14);CK(snp_stage_load((HANDLE)8,&root)==ERR(14)&&!loads);
 reset();bad_size=1;CK(snp_stage_load((HANDLE)8,&root)==ERR(33)&&!loads);
 reset();flag=2;CK(snp_stage_load((HANDLE)8,&root)==ERR(33)&&!loads);
 reset();bad_crc=1;CK(snp_stage_load((HANDLE)8,&root)==ERR(33)&&!loads&&!old);
 reset();open_status=ERR(14);CK(snp_stage_load((HANDLE)8,&root)==ERR(14)&&!loads);
 reset();load_status=ERR(26);CK(snp_stage_load((HANDLE)8,&root)==ERR(26)&&loads==1&&!starts&&!binds);
 reset();start_status=ERR(3);CK(snp_stage_load((HANDLE)8,&root)==ERR(3)&&starts==1&&!binds);
 reset();db.image=(HANDLE)7;CK(snp_stage_load((HANDLE)8,&root)==ERR(33)&&starts==1&&!supports&&!binds);
 reset();support_status=ERR(3);CK(snp_stage_load((HANDLE)8,&root)==ERR(3)&&supports==1&&!binds);
 reset();bind_status=ERR(7);CK(snp_stage_load((HANDLE)8,&root)==ERR(7)&&binds==1&&!pub);
 reset();snp_stage_inventory();CK(!loads&&!starts&&!reads&&!binds);return failure;
}
int get_checks(void){return checks;}
