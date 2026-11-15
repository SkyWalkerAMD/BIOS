/* Hardware-free DriverBinding and policy tests against the actual loader. */
#include "../source/common.c"
#include "../source/crc.c"
#include "../source/loader.c"
static BS bs;static RT rt;static ST st;
static int bad,checks,source_ok,usb_ok,tls_ok,dpc_ok,nii_ok,mode_bad,ns_error,ns_short,ns_flag,ns_changed;
static int load_failure,start_failure,bind_failure,stage_missing,load_count,start_count,bind_count,foreign_count,var_count;
static LOADED loaded_info[8];static uint8_t loaded_memory[8][65536];static int tamper_before,tamper_after;
static UN tpl;static unsigned stage_mask;static HANDLE image_handles[8],binding_handles[9],nii_handles[2];static DB dbs[9];
static uint8_t usb_path[]={2,1,8,0,1,2,3,4,0x7f,0xff,4,0};static uint8_t nii_path[49];static NII nii;
#define CHECK(x) do{checks++;if(!(x)){bad=__LINE__;return ERR(7);}}while(0)
#define TEST(x) do{checks++;if(!(x))return __LINE__;}while(0)
void say(const char *s){(void)s;}void status(const char *n,ES e){(void)n;(void)e;}
int i5_source_valid(void){return source_ok;}
int usb_target_handles(HANDLE out[2]){out[0]=(HANDLE)0x100;out[1]=(HANDLE)0x101;return usb_ok;}
void network_inventory(void){}
HANDLE network_candidate(void){return stage_mask==31&&nii_ok?(HANDLE)0x200:0;}
static UN EA raise_tpl(UN level){UN old=tpl;tpl=level;return old;}
static void EA restore_tpl(UN level){tpl=level;}
static ES EA free_pool(void *p){(void)p;return 0;}
static ES EA locate(GUID *g,void *r,void **out){(void)r;*out=0;
 if(eq(g,&tls_guid,16)){if(tls_ok){*out=(void *)0x1000;return 0;}return ERR(14);}
 if(eq(g,&dpc_guid,16)){if(dpc_ok){*out=(void *)0x1001;return 0;}return ERR(14);}
 return ERR(14);
}
static ES EA handles(uint32_t type,GUID *g,void *r,UN *n,HANDLE **out){(void)r;CHECK(type==2);
 if(eq(g,&binding_guid,16)){*n=9;*out=binding_handles;return 0;}
 if(eq(g,&nii_guid,16)){*n=nii_ok?(mode_bad==1?2:1):0;*out=nii_handles;return 0;}
 return ERR(14);
}
static ES EA handle(HANDLE h,GUID *g,void **out){*out=0;
 if(eq(g,&image_guid,16))for(unsigned i=0;i<8;i++)if(h==image_handles[i]){*out=&loaded_info[i];return 0;}
 if(eq(g,&binding_guid,16))for(unsigned i=0;i<9;i++)if(h==binding_handles[i]){*out=i==8?(void *)&dbs[8]:(void *)scoped[i].db;return *out?0:ERR(3);}
 if(eq(g,&dp_guid,16)){
  if(h==(HANDLE)0x100){*out=usb_path;return 0;}
  if(h==(HANDLE)0x200||h==(HANDLE)0x201){*out=nii_path;return 0;}
 }
 if(eq(g,&nii_guid,16)&&(h==(HANDLE)0x200||h==(HANDLE)0x201)){*out=&nii;return 0;}
 for(unsigned i=0;i<5;i++)if(eq(g,&services[i],16)&&h==(HANDLE)0x200){
  if(stage_mask&(1u<<i)){*out=(void *)(UN)(0x400+i);return 0;}return ERR(3);
 }
 return ERR(3);
}
static ES EA get_variable(C16 *name,GUID *g,uint32_t *attr,UN *n,void *data){
 CHECK(eq(name,W("NetworkStackVar"),32)&&eq(g,&nsvar,16)&&*n==8);var_count++;
 if(ns_error)return ERR(14);*n=ns_short?7:8;*attr=7;memset(data,0,8);((uint8_t *)data)[0]=(uint8_t)(ns_flag+(ns_changed&&var_count>1));return 0;
}
static ES EA unsupported(DB *db,HANDLE controller,void *path){(void)db;(void)controller;(void)path;foreign_count++;return ERR(7);}
static ES EA supported(DB *db,HANDLE controller,void *path){
 CHECK(path==0);unsigned j=0;while(j<8&&scoped[j].db!=db)j++;CHECK(j<8);unsigned i=spec[j].image;CHECK(db->image==image_handles[i]);
 if(i>=6){CHECK(controller==(HANDLE)0x100||controller==(HANDLE)0x101);
  if(controller!=(HANDLE)(UN)(i==6?0x100:0x101))return ERR(3);
 }else CHECK(controller==(HANDLE)0x200);
 return 0;
}
static ES EA start(DB *db,HANDLE controller,void *path){
 ES e=supported(db,controller,path);if(e)return e;unsigned j=0;while(j<8&&scoped[j].db!=db)j++;CHECK(j<8);unsigned i=spec[j].image;bind_count++;
 if((int)i==bind_failure)return ERR(7);
 if(i==7)nii_ok=1;
 if(i>=1&&i<=5&&(int)i!=stage_missing)stage_mask|=1u<<(i-1);
 return 0;
}
static ES EA stop(DB *d,HANDLE h,UN n,HANDLE *c){(void)n;(void)c;return supported(d,h,0);}
static ES EA load(uint8_t policy,HANDLE parent,void *path,void *buffer,UN bytes,HANDLE *out){
 CHECK(!policy&&parent==(HANDLE)0x77&&!path);int index=-1;
 for(unsigned i=0;i<8;i++)if(buffer==images[i].bytes&&bytes==images[i].length)index=(int)i;
 CHECK(index>=0);load_count++;if(index==load_failure)return ERR(26);
 *out=image_handles[index];UN base=(UN)loaded_memory[index];loaded_info[index].image_base=(void *)base;loaded_info[index].image_size=65536;
 for(unsigned j=0;j<8;j++)if(spec[j].image==(unsigned)index){const BIND_SPEC *p=&spec[j];DB *d=(DB *)(base+p->rva);
  *d=(DB){(void *)(base+p->supported+(index==tamper_before)),(void *)(base+p->start),(void *)(base+p->stop),p->version,0,0};
 }
 return 0;
}
static ES EA start_image(HANDLE h,UN *size,C16 **data){
 CHECK(!size&&!data);int index=-1;for(unsigned i=0;i<8;i++)if(h==image_handles[i])index=(int)i;
 CHECK(index>=0);start_count++;if(index==start_failure)return ERR(7);
 if(index==0)dpc_ok=1;
 for(unsigned j=0;j<8;j++)if(spec[j].image==(unsigned)index){
  SCOPED *s=&scoped[j];CHECK(s->db&&s->db->supported==scope_supported&&s->db->start==scope_start&&s->db->stop==scope_stop);
  s->db->image=h;s->db->binding=binding_handles[j];
  s->original.supported=supported;s->original.start=start;s->original.stop=stop;
  if(index==tamper_after)s->db->supported=supported;
 }
 return 0;
}
static void reset(void){
 memset(&bs,0,sizeof(bs));memset(&rt,0,sizeof(rt));memset(&st,0,sizeof(st));memset(loaded,0,sizeof(loaded));attempted=0;memset(scoped,0,sizeof(scoped));memset(loaded_info,0,sizeof(loaded_info));tamper_before=tamper_after=-1;
 bs.raise_tpl=raise_tpl;bs.restore_tpl=restore_tpl;bs.free_pool=free_pool;bs.locate_protocol=locate;bs.locate_handles=handles;bs.handle_protocol=handle;bs.load_image=load;bs.start_image=start_image;
 rt.get_variable=get_variable;st.bs=&bs;st.rt=&rt;gST=&st;
 source_ok=usb_ok=tls_ok=1;dpc_ok=nii_ok=mode_bad=ns_error=ns_short=ns_flag=ns_changed=0;
 load_failure=start_failure=bind_failure=stage_missing=-1;load_count=start_count=bind_count=foreign_count=var_count=0;tpl=4;stage_mask=0;bad=0;audit_len=0;
 for(unsigned i=0;i<8;i++){image_handles[i]=(HANDLE)(UN)(0x1000+i);binding_handles[i]=(HANDLE)(UN)(0x2000+i);dbs[i]=(DB){supported,start,0,0,0,binding_handles[i]};}
 binding_handles[8]=(HANDLE)0x9999;dbs[8]=(DB){unsupported,unsupported,0,0,(HANDLE)0x9998,binding_handles[8]};
 nii_handles[0]=(HANDLE)0x200;nii_handles[1]=(HANDLE)0x201;
 memset(nii_path,0,sizeof(nii_path));memcpy(nii_path,usb_path,8);nii_path[8]=3;nii_path[9]=11;nii_path[10]=37;memcpy(nii_path+45,usb_path+8,4);
 memset(&nii,0,sizeof(nii));nii.revision=0x20000;memcpy(nii.tag,"UNDI",4);nii.type=1;nii.major=3;nii.minor=1;
}
__declspec(dllexport) int run_tests(void){
 reset();TEST(i5_prepare_network((HANDLE)0x77)==0);TEST(load_count==8&&start_count==8&&bind_count==7&&var_count==2&&!foreign_count&&!bad);
 TEST(i5_prepare_network((HANDLE)0x77)==ERR(20)&&load_count==8);TEST(tpl==4);
 for(unsigned j=0;j<8;j++){
  TEST(scoped[j].db->supported(scoped[j].db,(HANDLE)0x9876,0)==ERR(3));
  TEST(scoped[j].db->start(scoped[j].db,(HANDLE)0x9876,0)==ERR(3));
  TEST(scoped[j].db->stop(scoped[j].db,(HANDLE)0x9876,0,0)==ERR(3));
 }
 TEST(scoped[4].db->supported(scoped[4].db,(HANDLE)0x200,0)==ERR(3));
 for(int i=1;i<8;i++){
  reset();tamper_before=i;TEST(i5_prepare_network((HANDLE)0x77)==ERR(33));
  reset();tamper_after=i;TEST(i5_prepare_network((HANDLE)0x77)==ERR(33));
  for(unsigned j=0;j<8;j++)if(spec[j].image==(unsigned)i)TEST(scoped[j].db->supported(scoped[j].db,(HANDLE)0x200,0)==ERR(3));
 }
 reset();ns_flag=1;TEST(i5_prepare_network((HANDLE)0x77)==0&&!foreign_count);
 reset();dpc_ok=nii_ok=1;stage_mask=31;TEST(i5_prepare_network((HANDLE)0x77)==0&&load_count==0&&bind_count==0);
 reset();source_ok=0;TEST(i5_prepare_network((HANDLE)0x77)==ERR(15)&&load_count==0);
 reset();usb_ok=0;TEST(i5_prepare_network((HANDLE)0x77)==ERR(14)&&load_count==0&&var_count==0);
 reset();tls_ok=0;TEST(i5_prepare_network((HANDLE)0x77)==ERR(14)&&load_count==0&&var_count==0);
 reset();tpl=8;TEST(i5_prepare_network((HANDLE)0x77)==ERR(15)&&load_count==0&&tpl==8);
 reset();ns_error=1;TEST(i5_prepare_network((HANDLE)0x77)==ERR(14)&&load_count==0);
 reset();ns_short=1;TEST(i5_prepare_network((HANDLE)0x77)==ERR(33)&&load_count==0);
 reset();ns_flag=2;TEST(i5_prepare_network((HANDLE)0x77)==ERR(33)&&load_count==0);
 reset();ns_changed=1;TEST(i5_prepare_network((HANDLE)0x77)==ERR(33));
 for(int i=0;i<8;i++){
  reset();load_failure=i;TEST(i5_prepare_network((HANDLE)0x77)==ERR(26));TEST(!foreign_count&&!bad);int old=load_count;TEST(i5_prepare_network((HANDLE)0x77)==ERR(20)&&old==load_count);
  reset();start_failure=i;TEST(i5_prepare_network((HANDLE)0x77)==ERR(7)&&!bad&&!foreign_count);
 }
 for(int i=1;i<8;i++){reset();bind_failure=i;TEST(i5_prepare_network((HANDLE)0x77)==ERR(7)&&!bad&&!foreign_count);}
 for(int i=1;i<=5;i++){reset();stage_missing=i;TEST(i5_prepare_network((HANDLE)0x77)==ERR(3)&&!bad);}
 reset();nii_ok=1;mode_bad=1;TEST(i5_prepare_network((HANDLE)0x77)==ERR(14)&&stage_mask==0);
 reset();nii_ok=1;nii_path[10]=36;TEST(i5_prepare_network((HANDLE)0x77)==ERR(14)&&stage_mask==0);
 reset();nii_ok=1;nii.type=0;TEST(i5_prepare_network((HANDLE)0x77)==ERR(14)&&stage_mask==0);
 return 0;
}
__declspec(dllexport) int get_checks(void){return checks;}
