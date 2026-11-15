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
 *data=0;*size=0;ES e=database->export(database,handle,size,0);
 if(e!=ERR(5)||*size<24||*size>8*1024*1024)return ERR(3);
 UN capacity=*size;e=gST->bs->allocate_pool(4,capacity,(void **)data);
 if(FAILED(e))return e;
 e=database->export(database,handle,size,*data);
 if(FAILED(e)||*size>capacity||*size<24){gST->bs->free_pool(*data);*data=0;return FAILED(e)?e:ERR(7);}
 return 0;
}
ES p5_bind(void){
 target=0;ES e=gST->bs->locate_protocol(&db_guid,0,(void **)&database);
 if(FAILED(e)||!database)return ERR(14);
 e=gST->bs->locate_protocol(&string_guid,0,(void **)&strings);if(FAILED(e)||!strings)return ERR(14);
 UN size=0;e=database->list(database,2,0,&size,0);
 if(e!=ERR(5)||!size||size%8||size>4096*8)return ERR(14);
 HANDLE *handles=0;UN capacity=size;
 e=gST->bs->allocate_pool(4,capacity,(void **)&handles);if(FAILED(e))return e;
 e=database->list(database,2,0,&size,handles);
 if(FAILED(e)||size>capacity||size%8){gST->bs->free_pool(handles);return FAILED(e)?e:ERR(7);}
 unsigned found=0;HANDLE selected=0;
 for(UN i=0;i<size/8;i++){
  uint8_t *data=0;UN n=0;
  if(FAILED(read_package(handles[i],&data,&n)))continue;
  if(p5_package_matches(data,n)){selected=handles[i];found++;}
  gST->bs->free_pool(data);
 }
 gST->bs->free_pool(handles);
 if(found!=1)return found?ERR(15):ERR(14);
 /* All supported languages and exact value IDs must already exist. No
  * NewString call can silently allocate an ID belonging to native Setup. */
 for(unsigned l=0;l<P5_LANG_COUNT;l++)for(unsigned i=0;i<V_COUNT;i++){
  C16 current[160];UN n=sizeof(current);
  e=strings->get(strings,p5_languages[l],selected,p5_value_ids[i],current,&n,0);
  if(FAILED(e)||n<2||n>sizeof(current)||n%2||current[n/2-1])return ERR(33);
 }
 target=selected;return 0;
}
ES p5_publish(void){
 if(!target||!strings)return ERR(6);
 uint8_t *data=0;UN n=0;ES e=read_package(target,&data,&n);
 if(FAILED(e))return e;
 int match=p5_package_matches(data,n);gST->bs->free_pool(data);
 if(!match){target=0;return ERR(33);}
 for(unsigned l=0;l<P5_LANG_COUNT;l++)for(unsigned i=0;i<V_COUNT;i++){
  C16 desired[160],actual[160];unsigned j=0;
  while(j<159&&values[i][j]){desired[j]=(uint8_t)values[i][j];j++;}desired[j]=0;
  if(values[i][j])return ERR(4);
  e=strings->set(strings,target,p5_value_ids[i],p5_languages[l],desired,0);if(FAILED(e))return e;
  UN bytes=sizeof(actual);e=strings->get(strings,p5_languages[l],target,p5_value_ids[i],actual,&bytes,0);
  if(FAILED(e)||bytes!=(j+1)*2||!eq(desired,actual,bytes))return ERR(7);
 }
 logtext("P5_NATIVE_STRINGS_PUBLISHED_AND_READ_BACK\r\n");return 0;
}
void p5_release(void){target=0;database=0;strings=0;}
