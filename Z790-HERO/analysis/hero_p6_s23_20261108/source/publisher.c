/* Bind to an exact precompiled P5 readonly or P6 Setup resource.
 * Known complete Forms are byte-equal whitelisted; never accept a subset.
 * P5 publishes 40 existing values; P6 publishes all 41, including apply status.
 * Never adds/replaces forms, installs ConfigAccess or changes NVRAM/Setup data. */
#include "p5.h"
#include "expected.h"
#include "expected_p5.h"
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
enum {RESOURCE_NONE,RESOURCE_P5_READONLY,RESOURCE_P6};
static unsigned target_kind,target_values;
_Static_assert(P5_READONLY_VALUE_COUNT==40&&V_COUNT==41,"known resource value ABI");
/* Bounded diagnostic metadata; values are stage-specific sizes/indices.
 * These are cached RAM records, never console output from a TPL8 callback. */
static void trace(const char *stage,ES status,UN a,UN b){
 logtext("P6_NATIVE_STAGE=");logtext(stage);logtext(" STATUS=");loghex(status,16);
 logtext(" A=");loghex(a,8);logtext(" B=");loghex(b,8);logtext("\r\n");
}
/* Exact contents, including all original IFR. A CRC collision cannot admit
 * another firmware. The exporter has a separate allocation-capacity check. */
int p5_package_kind(const uint8_t *b,UN n){
 if(!b||n<24||n>8*1024*1024||u32(b+16)!=n)return -1;
 unsigned forms=0,kind=RESOURCE_NONE,ended=0;
 for(UN p=20;p<n;){
  if(n-p<4)return -1;UN size=u32(b+p)&0xffffff;
  if(size<4||size>n-p)return -1;
  if(b[p+3]==2){
   forms++;
   if(size==sizeof(p5_expected_forms)&&eq(b+p,p5_expected_forms,size))kind=RESOURCE_P6;
   else if(size==sizeof(p5_readonly_forms)&&eq(b+p,p5_readonly_forms,size))kind=RESOURCE_P5_READONLY;
  }
  if(b[p+3]==0xdf){if(size!=4||p+size!=n)return -1;ended=1;}
  p+=size;
 }return forms==1&&ended?(int)kind:-1;
}
/* Preserve the legacy helper's strict P6 contract for existing callers/tests. */
int p5_package_matches(const uint8_t *b,UN n){return p5_package_kind(b,n)==RESOURCE_P6;}
static ES read_package(HANDLE handle,uint8_t **data,UN *size){
 *data=0;*size=0;ES e=database->export(database,handle,size,0);
 if(e!=ERR(5)||*size<24||*size>8*1024*1024){trace("EXPORT_SIZE",e,*size,0);return ERR(3);}
 UN capacity=*size;e=gST->bs->allocate_pool(4,capacity,(void **)data);
 if(FAILED(e)){trace("EXPORT_ALLOCATE",e,capacity,0);return e;}
 e=database->export(database,handle,size,*data);
 if(FAILED(e)||*size>capacity||*size<24){trace("EXPORT_DATA",e,*size,capacity);gST->bs->free_pool(*data);*data=0;return FAILED(e)?e:ERR(7);}
 return 0;
}
static ES check_strings(HANDLE handle,unsigned count,const char *stage){
 if(!strings||!handle||(count!=P5_READONLY_VALUE_COUNT&&count!=V_COUNT))return ERR(33);
 for(unsigned l=0;l<P5_LANG_COUNT;l++)for(unsigned i=0;i<count;i++){
  C16 current[160];UN n=sizeof(current);
  ES e=strings->get(strings,p5_languages[l],handle,p5_value_ids[i],current,&n,0);
  if(FAILED(e)||n<2||n>sizeof(current)||n%2||current[n/2-1]){
   trace(stage,e,l,i);logtext("P6_NATIVE_STRING_LANGUAGE=");logtext(p5_languages[l]);
   logtext(" ID=");loghex(p5_value_ids[i],4);logtext(" BYTES=");loghex(n,8);logtext("\r\n");return ERR(33);
  }
 }
 return 0;
}
static void log_resource(unsigned kind){
 logtext("P6_NATIVE_RESOURCE_KIND=");
 logtext(kind==RESOURCE_P5_READONLY?"P5_READONLY VALUES=40":"P6_CONFIG VALUES=41");
 logtext(" FORMS_BYTES=");loghex(kind==RESOURCE_P5_READONLY?sizeof(p5_readonly_forms):sizeof(p5_expected_forms),8);
 logtext(" SHA256=");logtext(kind==RESOURCE_P5_READONLY?P5_READONLY_FORM_SHA256:P6_FORM_SHA256);logtext("\r\n");
}
ES p5_bind(void){
 target=0;target_kind=target_values=0;ES e=gST->bs->locate_protocol(&db_guid,0,(void **)&database);
 if(FAILED(e)||!database){trace("BIND_HII_DATABASE",e,database?1:0,0);return ERR(14);}
 e=gST->bs->locate_protocol(&string_guid,0,(void **)&strings);if(FAILED(e)||!strings){trace("BIND_HII_STRING",e,strings?1:0,0);return ERR(14);}
 UN size=0;e=database->list(database,2,0,&size,0);
 if(e!=ERR(5)||!size||size%8||size>4096*8){trace("BIND_LIST_SIZE",e,size,4096*8);return ERR(14);}
 HANDLE *handles=0;UN capacity=size;
 e=gST->bs->allocate_pool(4,capacity,(void **)&handles);if(FAILED(e)){trace("BIND_LIST_ALLOCATE",e,capacity,0);return e;}
 e=database->list(database,2,0,&size,handles);
 if(FAILED(e)||size>capacity||size%8){trace("BIND_LIST_DATA",e,size,capacity);gST->bs->free_pool(handles);return FAILED(e)?e:ERR(7);}
 unsigned found=0,selected_kind=RESOURCE_NONE;HANDLE selected=0;
 for(UN i=0;i<size/8;i++){
  uint8_t *data=0;UN n=0;
  e=read_package(handles[i],&data,&n);
  if(FAILED(e)){trace("BIND_EXPORT_HANDLE",e,i,size/8);gST->bs->free_pool(handles);return e;}
  int classified=p5_package_kind(data,n);
  if(classified<0){trace("BIND_PACKAGE_FORMAT",ERR(33),i,n);gST->bs->free_pool(data);gST->bs->free_pool(handles);return ERR(33);}
  unsigned kind=(unsigned)classified;
  if(kind){selected=handles[i];selected_kind=kind;found++;}
  gST->bs->free_pool(data);
 }
 gST->bs->free_pool(handles);
 trace("BIND_ENUM_COMPLETE",0,size/8,found);
 if(found!=1)return found?ERR(15):ERR(14);
 /* All supported languages and exact value IDs must already exist. No
  * NewString call can silently allocate an ID belonging to native Setup. */
 unsigned count=selected_kind==RESOURCE_P5_READONLY?P5_READONLY_VALUE_COUNT:V_COUNT;
 e=check_strings(selected,count,"BIND_STRING_CHECK");if(FAILED(e))return e;
 target=selected;target_kind=selected_kind;target_values=count;log_resource(target_kind);return 0;
}
ES p5_publish(void){
 if(!target||!strings||!target_kind)return ERR(6);
 uint8_t *data=0;UN n=0;ES e=read_package(target,&data,&n);
 if(FAILED(e))return e;
 unsigned kind=(unsigned)p5_package_kind(data,n);gST->bs->free_pool(data);
 unsigned count=target_kind==RESOURCE_P5_READONLY?P5_READONLY_VALUE_COUNT:V_COUNT;
 if(kind!=target_kind||count!=target_values){trace("PUBLISH_KIND_CHANGED",ERR(33),target_kind,kind);target=0;target_kind=target_values=0;return ERR(33);}
 /* Recheck every selected existing ID/language before the first SetString;
  * a later firmware-service failure remains reported and is never replayed. */
 e=check_strings(target,count,"PUBLISH_STRING_CHECK");if(FAILED(e))return e;
 for(unsigned l=0;l<P5_LANG_COUNT;l++)for(unsigned i=0;i<count;i++){
  C16 desired[160],actual[160];unsigned j=0;
  while(j<159&&values[i][j]){desired[j]=(uint8_t)values[i][j];j++;}desired[j]=0;
  if(values[i][j])return ERR(4);
  e=strings->set(strings,target,p5_value_ids[i],p5_languages[l],desired,0);if(FAILED(e))return e;
  UN bytes=sizeof(actual);e=strings->get(strings,p5_languages[l],target,p5_value_ids[i],actual,&bytes,0);
  if(FAILED(e)||bytes!=(j+1)*2||!eq(desired,actual,bytes))return ERR(7);
 }
 logtext("P5_NATIVE_STRINGS_PUBLISHED_AND_READ_BACK\r\n");return 0;
}
void p5_release(void){target=0;target_kind=target_values=0;database=0;strings=0;}
