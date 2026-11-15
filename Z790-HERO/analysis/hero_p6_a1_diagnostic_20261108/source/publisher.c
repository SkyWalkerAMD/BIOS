/* Bind to the exact precompiled P5 Setup resource, updating only new strings.
 * Never adds/replaces forms, installs ConfigAccess or changes NVRAM/Setup data. */
#include "p5.h"
#include "expected.h"
typedef struct DB DB;
struct DB {
 void *add,*remove,*update;
 ES(EA *list)(DB *,uint8_t,const GUID *,UN *,HANDLE *);
 ES(EA *export)(DB *,HANDLE,UN *,void *);
};
typedef struct STR STR;
struct STR {
 void *add;
 ES(EA *get)(STR *,const char *,HANDLE,uint16_t,C16 *,UN *,void **);
 ES(EA *set)(STR *,HANDLE,uint16_t,const char *,const C16 *,const void *);
};
static GUID db_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID string_guid={0x0fd96974,0x23aa,0x4cdc,{0xb9,0xcb,0x98,0xd1,0x77,0x50,0x32,0x2a}};
static DB *database;static STR *strings;static HANDLE target;
/* Diagnostic wrappers preserve exact protocol arguments. They log before each
 * synchronous external call, in application context only, without new events. */
static ES locate(GUID *g,void **p,const char *name){
 if(!a1_before(name,0,0,0))return ERR(9);ES e=gST->bs->locate_protocol(g,0,p);a1_after(name,e,(UN)*p);return e;
}
static ES db_list(UN *n,HANDLE *p){
 if(!a1_before("HII_LIST",*n,(UN)p,0))return ERR(9);ES e=database->list(database,2,0,n,p);a1_after("HII_LIST",e,*n);return e;
}
static ES db_export(HANDLE h,UN *n,void *p){
 if(!a1_before("HII_EXPORT",(UN)h,*n,(UN)p))return ERR(9);ES e=database->export(database,h,n,p);a1_after("HII_EXPORT",e,*n);return e;
}
static ES alloc(UN n,void **p){
 if(!a1_before("HII_ALLOC",n,0,0))return ERR(9);ES e=gST->bs->allocate_pool(4,n,p);a1_after("HII_ALLOC",e,(UN)*p);return e;
}
static void release(void *p){
 /* Cleanup cannot be skipped if recording reaches its limit. */
 a1_before("HII_FREE",(UN)p,0,0);ES e=gST->bs->free_pool(p);a1_after("HII_FREE",e,0);
 if(FAILED(e))audit_bad=1;
}
static ES get(unsigned l,HANDLE h,unsigned id,C16 *p,UN *n){
 if(!a1_before("HII_GET_STRING",l,id,*n))return ERR(9);ES e=strings->get(strings,p5_languages[l],h,(uint16_t)id,p,n,0);a1_after("HII_GET_STRING",e,*n);return e;
}
static ES set(unsigned l,HANDLE h,unsigned id,const C16 *p){
 if(!a1_before("HII_SET_STRING",l,id,(UN)h))return ERR(9);ES e=strings->set(strings,h,(uint16_t)id,p5_languages[l],p,0);a1_after("HII_SET_STRING",e,0);return e;
}
/* Exact contents, including all original IFR. A CRC collision cannot admit
 * another firmware. The exporter has a separate allocation-capacity check. */
int p5_package_matches(const uint8_t *b,UN n){
 if(!b||n<24||n>8*1024*1024||u32(b+16)!=n)return 0;
 unsigned forms=0,match=0,ended=0;
 for(UN p=20;p<n;){
  if(n-p<4)return 0;UN size=u32(b+p)&0xffffff;
  if(size<4||size>n-p)return 0;
  if(b[p+3]==2){forms++;match+=size==sizeof(p5_expected_forms)&&eq(b+p,p5_expected_forms,size);}
  if(b[p+3]==0xdf){if(size!=4||p+size!=n)return 0;ended=1;}
  p+=size;
 }return forms==1&&match==1&&ended;
}
static ES read_package(HANDLE handle,uint8_t **data,UN *size){
 *data=0;*size=0;ES e=db_export(handle,size,0);
 if(e!=ERR(5)||*size<24||*size>8*1024*1024)return ERR(3);
 UN capacity=*size;e=alloc(capacity,(void **)data);
 if(FAILED(e))return e;
 e=db_export(handle,size,*data);
 if(FAILED(e)||*size>capacity||*size<24){release(*data);*data=0;return FAILED(e)?e:ERR(7);}
 return 0;
}
ES p5_bind(void){
 target=0;ES e=locate(&db_guid,(void **)&database,"LOCATE_HII_DATABASE");
 if(FAILED(e)||!database)return ERR(14);
 e=locate(&string_guid,(void **)&strings,"LOCATE_HII_STRING");if(FAILED(e)||!strings)return ERR(14);
 UN size=0;e=db_list(&size,0);
 if(e!=ERR(5)||!size||size%8||size>4096*8)return ERR(14);
 HANDLE *handles=0;UN capacity=size;
 e=alloc(capacity,(void **)&handles);if(FAILED(e))return e;
 e=db_list(&size,handles);
 if(FAILED(e)||size>capacity||size%8){release(handles);return FAILED(e)?e:ERR(7);}
 unsigned found=0;HANDLE selected=0;
 for(UN i=0;i<size/8;i++){
  if(audit_bad){release(handles);return ERR(9);}
  if(!a1_before("HII_HANDLE_INDEX",i,size/8,(UN)handles[i])){release(handles);return ERR(9);}
  uint8_t *data=0;UN n=0;
  if(FAILED(read_package(handles[i],&data,&n)))continue;
  if(p5_package_matches(data,n)){selected=handles[i];found++;}
  release(data);
 }
 release(handles);if(audit_bad)return ERR(9);
 if(found!=1)return found?ERR(15):ERR(14);
 /* All supported languages and exact value IDs must already exist. No
  * NewString call can silently allocate an ID belonging to native Setup. */
 for(unsigned l=0;l<P5_LANG_COUNT;l++)for(unsigned i=0;i<V_COUNT;i++){
  C16 current[160];UN n=sizeof(current);
  e=get(l,selected,p5_value_ids[i],current,&n);
  if(FAILED(e)||n<2||n>sizeof(current)||n%2||current[n/2-1])return ERR(33);
 }
 target=selected;return 0;
}
ES p5_publish(void){
 if(!target||!strings)return ERR(6);
 uint8_t *data=0;UN n=0;ES e=read_package(target,&data,&n);
 if(FAILED(e))return e;
 int match=p5_package_matches(data,n);release(data);
 if(!match){target=0;return ERR(33);}
 for(unsigned l=0;l<P5_LANG_COUNT;l++)for(unsigned i=0;i<V_COUNT;i++){
  C16 desired[160],actual[160];UN desired_bytes;
  if(i==V_CONFIG_STATUS){
   /* This application does not evaluate or apply settings. Preserve this
    * pre-existing string separately in every language, including Unicode. */
   desired_bytes=sizeof(desired);e=get(l,target,p5_value_ids[i],desired,&desired_bytes);
   if(FAILED(e)||desired_bytes<2||desired_bytes>sizeof(desired)||desired_bytes%2||desired[desired_bytes/2-1])return ERR(33);
  }else{
   unsigned j=0;while(j<159&&values[i][j]){desired[j]=(uint8_t)values[i][j];j++;}desired[j]=0;
   if(values[i][j])return ERR(4);desired_bytes=(j+1)*2;
  }
  e=set(l,target,p5_value_ids[i],desired);if(FAILED(e))return e;
  UN bytes=sizeof(actual);e=get(l,target,p5_value_ids[i],actual,&bytes);
  if(FAILED(e)||bytes!=desired_bytes||!eq(desired,actual,bytes))return ERR(7);
 }
 logtext("P5_NATIVE_STRINGS_PUBLISHED_AND_READ_BACK\r\n");return 0;
}
ES p5_probe_same_value(void){
 if(!target||!strings)return ERR(6);
 uint8_t *data=0;UN n=0;ES e=read_package(target,&data,&n);if(FAILED(e))return e;
 int match=p5_package_matches(data,n);release(data);if(!match){target=0;return ERR(33);}
 C16 before[160],after[160];UN have=sizeof(before),got=sizeof(after);
 e=get(0,target,p5_value_ids[0],before,&have);
 if(FAILED(e)||have<2||have>sizeof(before)||have%2||before[have/2-1])return ERR(33);
 /* Use precisely the current string, never a generated placeholder. */
 e=set(0,target,p5_value_ids[0],before);if(FAILED(e))return e;
 e=get(0,target,p5_value_ids[0],after,&got);
 if(FAILED(e)||got!=have||!eq(before,after,have))return ERR(7);
 logtext("A1_SINGLE_SAME_VALUE_SET_AND_READ_BACK_OK\r\n");return 0;
}
void p5_release(void){target=0;database=0;strings=0;}
