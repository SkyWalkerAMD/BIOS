/* Append one verified Advanced-menu reference and five read-only forms to the
 * existing HERO Setup package IN RAM. Preserve every existing IFR byte.
 * Never changes Setup variables, AMITSE code, capsules, or flash. */
#include "native.h"
#include "native_forms.h"
#include "tse_audit.h"
static GUID db_guid={0xef9fc172,0xa1b2,0x4693,{0xb3,0x27,0x6d,0x32,0xfc,0x41,0x60,0x42}};
static GUID str_guid={0x0fd96974,0x23aa,0x4cdc,{0xb9,0xcb,0x98,0xd1,0x77,0x50,0x32,0x2a}};
static GUID form_guid={0x7b59104a,0xc00d,0x4158,{0x87,0xff,0xf0,0x4d,0x63,0x96,0xa9,0x15}};
static NDB *db;static NSTR *strings;static HANDLE native_handle;
static uint8_t *original,*replacement;static UN original_n,replacement_n;
static unsigned attached,dirty;
static uint16_t string_ids[sizeof(native_strings)/sizeof(native_strings[0])];
static void number(const char *name,uint64_t value){logtext(name);loghex(value,16);logtext("\r\n");}
static ES alloc(UN n,void **p){*p=0;return gST->bs->allocate_pool(4,n,p);}
static int find_forms(const uint8_t *b,UN n,UN *offset,UN *length){
 if(!b||n<24||u32(b+16)!=n)return 0;unsigned count=0,match=0,ended=0;
 for(UN p=20;p<n;){
  if(n-p<4)return 0;UN size=u32(b+p)&0xffffffU;uint8_t type=b[p+3];
  if(size<4||size>n-p)return 0;
  if(type==2){
   count++;if(size>=43&&b[p+4]==0xe&&eq(b+p+6,&form_guid,16)){
    match++;*offset=p;*length=size;
   }
  }
  if(type==0xdf){if(size!=4||p+size!=n)return 0;ended=1;}
  p+=size;
 }
 return ended&&count==1&&match==1;
}
static ES export(HANDLE h,uint8_t **out,UN *n){
 *out=0;*n=0;ES e=db->export(db,h,n,0);if(e!=ERR(5)||*n<24||*n>8*1024*1024)return ERR(3);
 e=alloc(*n,(void **)out);if(FAILED(e))return e;
 e=db->export(db,h,n,*out);if(FAILED(e)){gST->bs->free_pool(*out);*out=0;}return e;
}
static void wide(C16 *out,const char *s){unsigned i=0;while(i<159&&s[i]){out[i]=(uint8_t)s[i];i++;}out[i]=0;}
int native_is_attached(void){return attached!=0;}
ES native_audit(void){
 if(!attached||!replacement)return ERR(6);
 return tse_snapshot("RESIDENT_CHECK",native_handle,replacement+20,replacement_n-24);
}
ES native_publish(void){
 if(!attached)return 0;
 for(unsigned i=0;i<V_COUNT;i++){
  C16 w[160];wide(w,values[i]);ES e=strings->set(strings,native_handle,string_ids[native_value_ids[i]-1],"en-US",w,0);
  if(FAILED(e)){number("NATIVE_STRING_FAILED=",e);return e;}
 }return 0;
}
ES native_attach(void){
 if(attached)return native_publish();if(dirty)return ERR(15);
 if(!same(report.board,"ROG MAXIMUS Z790 HERO")||!same(report.bios,"3107")||FAILED(last_refresh))return ERR(15);
 ES e=gST->bs->locate_protocol(&db_guid,0,(void **)&db);if(FAILED(e)||!db)return ERR(14);
 e=gST->bs->locate_protocol(&str_guid,0,(void **)&strings);if(FAILED(e)||!strings)return ERR(14);
 UN size=0;HANDLE *handles=0;e=db->list(db,2,0,&size,0);
 if(e!=ERR(5)||!size||size%sizeof(HANDLE)||size>4096*sizeof(HANDLE))return ERR(3);
 if(FAILED(e=alloc(size,(void **)&handles)))return e;
 e=db->list(db,2,0,&size,handles);if(FAILED(e)){gST->bs->free_pool(handles);return e;}
 uint8_t *selected=0;UN selected_n=0,offset=0,length=0;unsigned matches=0;
 for(UN i=0;i<size/sizeof(HANDLE);i++){
  uint8_t *buf=0;UN n=0,off=0,len=0;if(FAILED(export(handles[i],&buf,&n)))continue;
  if(find_forms(buf,n,&off,&len)){
   matches++;
   if(matches==1){selected=buf;selected_n=n;native_handle=handles[i];offset=off;length=len;buf=0;}
  }
  if(buf)gST->bs->free_pool(buf);
 }
 gST->bs->free_pool(handles);(void)selected_n;
 if(matches!=1){if(selected)gST->bs->free_pool(selected);number("NATIVE_TARGET_MATCHES=",matches);return ERR(14);}
 size_t at=0,end=0;
 if(!native_form_bounds(selected+offset,length,&at,&end)){gST->bs->free_pool(selected);logtext("NATIVE_IFR_TARGET_MISMATCH\r\n");return ERR(33);}
 number("NATIVE_ADVANCED_INSERT=",at);number("NATIVE_ORIGINAL_FORM_BYTES=",length);
 original_n=20+length+4;e=alloc(original_n,(void **)&original);if(FAILED(e))goto finish;
 memcpy(original,selected,20);*(uint32_t *)(original+16)=(uint32_t)original_n;
 memcpy(original+20,selected+offset,length);*(uint32_t *)(original+20+length)=0xdf000004U;
 for(unsigned i=0;i<sizeof(native_strings)/sizeof(native_strings[0]);i++){
  C16 w[160];wide(w,native_strings[i]);string_ids[i]=0;
  e=strings->new_string(strings,native_handle,&string_ids[i],"en-US",0,w,0);
  if(FAILED(e)||!string_ids[i]){e=FAILED(e)?e:ERR(7);goto finish;}
 }
 uint8_t extra[sizeof(native_form_template)];memcpy(extra,native_form_template,sizeof(extra));
 for(unsigned i=0;i<sizeof(native_string_offsets)/sizeof(native_string_offsets[0]);i++){
  unsigned pos=native_string_offsets[i];uint16_t old=u16(extra+pos);
  if(!old||old>sizeof(native_strings)/sizeof(native_strings[0])){e=ERR(33);goto finish;}
  uint16_t id=string_ids[old-1];extra[pos]=(uint8_t)id;extra[pos+1]=(uint8_t)(id>>8);
 }
 replacement_n=original_n+15+sizeof(extra);e=alloc(replacement_n,(void **)&replacement);if(FAILED(e))goto finish;
 memcpy(replacement,original,20);*(uint32_t *)(replacement+16)=(uint32_t)replacement_n;
 size_t new_n=0;
 if(!native_splice(original+20,length,extra,sizeof(extra),string_ids[NATIVE_TITLE-1],string_ids[NATIVE_HELP-1],replacement+20,replacement_n-24,&new_n)){
  e=ERR(33);goto finish;
 }
 *(uint32_t *)(replacement+20+new_n)=0xdf000004U;
 /* Retain the original before UpdatePackageList, including any partial failure. */
 /* Fail before mutation if this firmware's bounded cache audit is unavailable. */
 e=tse_snapshot("BEFORE_UPDATE",native_handle,original+20,original_n-24);
 if(FAILED(e))goto finish;
 dirty=1;e=db->update(db,native_handle,replacement);number("NATIVE_UPDATE_STATUS=",e);
 number("TSE_AFTER_UPDATE_AUDIT=",tse_snapshot("AFTER_UPDATE",native_handle,replacement+20,replacement_n-24));
 if(!FAILED(e)){
  uint8_t *check=0;UN n=0,off=0,len=0;e=export(native_handle,&check,&n);
  if(!FAILED(e)&&(!find_forms(check,n,&off,&len)||len!=new_n||!eq(check+off,replacement+20,new_n)))e=ERR(7);
  if(check)gST->bs->free_pool(check);
  if(!FAILED(e)){attached=1;e=native_publish();logtext("NATIVE_ADVANCED_IPMI_INSTALLED\r\n");}
 }
 if(FAILED(e)&&dirty){ES rollback=db->update(db,native_handle,original);number("NATIVE_ATTACH_ROLLBACK=",rollback);if(!FAILED(rollback)){dirty=0;attached=0;}}
finish:
 gST->bs->free_pool(selected);
 if(!dirty){if(original){gST->bs->free_pool(original);original=0;}if(replacement){gST->bs->free_pool(replacement);replacement=0;}}
 return e;
}
ES native_detach(void){
 if(!dirty)return 0;
 uint8_t *check=0;UN n=0,off=0,len=0;ES e=export(native_handle,&check,&n);
 if(!FAILED(e)&&(!find_forms(check,n,&off,&len)||len!=replacement_n-24||!eq(check+off,replacement+20,len)))e=ERR(15);
 if(check)gST->bs->free_pool(check);if(FAILED(e)){number("NATIVE_DETACH_CHANGED=",e);return e;}
 e=db->update(db,native_handle,original);number("NATIVE_RESTORE_STATUS=",e);if(FAILED(e))return e;
 check=0;n=off=len=0;e=export(native_handle,&check,&n);
 if(!FAILED(e)&&(!find_forms(check,n,&off,&len)||len!=original_n-24||!eq(check+off,original+20,len)))e=ERR(7);
 if(check)gST->bs->free_pool(check);number("NATIVE_RESTORE_READBACK=",e);if(FAILED(e))return e;
 number("TSE_RESTORE_AUDIT=",tse_snapshot("AFTER_RESTORE",native_handle,original+20,original_n-24));
 attached=dirty=0;gST->bs->free_pool(original);gST->bs->free_pool(replacement);original=replacement=0;return 0;
}
