#include "internal.h"
typedef ES(EA *GET_STRING)(STRINGS*,const char*,HANDLE,uint16_t,C16*,UN*,void**);
static C16 *texts[6]={U("Ai Tweaker Password"),U("Set or change the independent password."),
 U("Clear Ai Tweaker Password"),U("Current password is required to clear protection."),
 U("Verify Ai Tweaker Password"),U("Unlock for this BIOS visit.")};
static int get_languages(MP_STATE*s,uint64_t ticket){
 char all[512];UN n=sizeof(all);memset(all,0xa5,sizeof(all));
 if(!mp_window(s,ticket))return 0;
 ES status=s->binding.strings->languages(s->binding.strings,s->binding.hii,all,&n);
 if(!mp_window(s,ticket)||FAILED(status)||!n||n>sizeof(all))return 0;
 UN used=0;while(used<n&&all[used])used++;if(used==n)return 0;n=used+1;
 unsigned count=0;UN at=0;
 while(at<n-1){
  if(count==MP_MAX_LANGUAGES)return 0;UN begin=at;
  while(at<n-1&&all[at]!=';'){
   char c=all[at];if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'))return 0;at++;
  }
  UN size=at-begin;if(!size||size>=32)return 0;
  memcpy(s->languages[count],all+begin,size);s->languages[count][size]=0;
  /* Keyword/config languages are not UI translations and are never modified
   * as if they were. Unknown layouts stop before any string mutation. */
  if(size>=6&&!memcmp(s->languages[count],"x-UEFI",6))return 0;
  for(unsigned i=0;i<count;i++)if(!memcmp(s->languages[i],s->languages[count],32))return 0;
  count++;if(at<n-1){at++;if(at==n-1)return 0;}
 }
 s->language_count=count;return count>0;
}
static int string_equal(MP_STATE*s,uint64_t ticket,unsigned language,uint16_t id,const C16*expected){
 C16 value[256];UN n=sizeof(value);memset(value,0xa5,sizeof(value));
 if(!mp_window(s,ticket))return 0;
 ES status=((GET_STRING)s->binding.strings->get_string)(s->binding.strings,s->languages[language],s->binding.hii,id,value,&n,0);
 if(!mp_window(s,ticket)||FAILED(status)||n<2||n>sizeof(value)||n%2||value[n/2-1])return 0;
 UN expected_size=0;while(expected[expected_size]){if(++expected_size>=255)return 0;}
 return n==(expected_size+1)*2&&!memcmp(value,expected,n);
}
static int strings_absent(MP_STATE*s,uint64_t ticket){
 for(unsigned i=0;i<6;i++){if(s->tokens[i]){for(unsigned lang=0;lang<s->language_count;lang++){
  C16 value[2];UN n=sizeof(value);if(!mp_window(s,ticket))return 0;
  ES status=((GET_STRING)s->binding.strings->get_string)(s->binding.strings,s->languages[lang],s->binding.hii,s->tokens[i],value,&n,0);
  if(!mp_window(s,ticket)||(status!=ERR(14)&&status!=ERR(2)))return 0;
 }}}return 1;
}
static int add_strings(MP_STATE*s,uint64_t ticket){
 for(unsigned i=0;i<6;i++){
  if(!mp_window(s,ticket))return 0;s->dirty=1;s->stage=MP_STRINGS;
  uint16_t token=0;ES status=s->binding.strings->new_string(s->binding.strings,s->binding.hii,&token,s->languages[0],0,texts[i],0);
  /* Retain an output ID only when it cannot alias a pre-existing string.
   * Even a failed NewString may have mutated HII: dirty was set beforehand. */
  if(token>s->previous_max_token)s->tokens[i]=token;
  if(!mp_window(s,ticket)||FAILED(status)||!token||token<=s->previous_max_token)return 0;
  for(unsigned previous=0;previous<i;previous++)if(token==s->tokens[previous])return 0;
  if(!string_equal(s,ticket,0,token,texts[i]))return 0;
  for(unsigned lang=1;lang<s->language_count;lang++){
   if(!mp_window(s,ticket))return 0;
   status=s->binding.strings->set_string(s->binding.strings,s->binding.hii,token,s->languages[lang],texts[i],0);
   if(!mp_window(s,ticket)||FAILED(status)||!string_equal(s,ticket,lang,token,texts[i]))return 0;
  }
 }return 1;
}
static int recoverable(MP_STATE*s,const uint8_t*current,UN n){
 const uint8_t*form=0;UN fn=0;uint16_t maximum=0;
 if(!mp_package(current,n,&form,&fn,&maximum))return 0;
 if(!mp_original_forms(form,fn)){
  const uint8_t*published=0;UN pn=0;
  if(!s->published_package||!mp_package(s->published_package,s->published_size,&published,&pn,&maximum)||pn!=fn||memcmp(form,published,fn))return 0;
 }
 UN a=20,b=20;
 for(;;){
  if(s->original_size-a<4||n-b<4)return 0;uint32_t ah=mp_u32(s->original_package+a),bh=mp_u32(current+b),an=ah&0xffffff,bn=bh&0xffffff;
  if(an<4||an>s->original_size-a||bn<4||bn>n-b||(ah>>24)!=(bh>>24))return 0;
  if((ah>>24)==4){if(an<48||bn<an||s->original_package[a+an-1]||memcmp(s->original_package+a+4,current+b+4,an-5))return 0;}
  else if((ah>>24)!=2&&(an!=bn||memcmp(s->original_package+a,current+b,an)))return 0;
  if((ah>>24)==0xdf)return a+an==s->original_size&&b+bn==n;a+=an;b+=bn;
 }
}
static MP_RESULT restore(MP_STATE*s,uint64_t ticket){
 if(!mp_window(s,ticket)||!mp_identity(s,1)||!mp_window(s,ticket)){s->stage=s->ended?MP_TERMINAL:MP_RECOVERY_REQUIRED;return s->ended?MP_ENDED:MP_DIRTY;}
 if(!s->original_package||!s->original_size)return MP_INVALID;
 UN n=0;uint8_t*current=mp_export(s,ticket,&n);
 /* A vanished, reassigned or foreign package handle is not ours to repair. */
 if(!current||!recoverable(s,current,n)){mp_free(s,current);s->stage=MP_RECOVERY_REQUIRED;return MP_DIRTY;}
 mp_free(s,current);
 if(!mp_window(s,ticket))return MP_DIRTY;
 ES status=s->binding.database->update_list(s->binding.database,s->binding.hii,s->original_package);
 if(!mp_window(s,ticket)){s->stage=s->ended?MP_TERMINAL:MP_RECOVERY_REQUIRED;return s->ended?MP_ENDED:MP_DIRTY;}
 current=mp_export(s,ticket,&n);int exact=current&&n==s->original_size&&!memcmp(current,s->original_package,n);mp_free(s,current);
 if(!exact||!strings_absent(s,ticket)||!mp_identity(s,1)||!mp_window(s,ticket)){
  s->stage=s->ended?MP_TERMINAL:MP_RECOVERY_REQUIRED;return s->ended?MP_ENDED:MP_DIRTY;
 }
 if(!s->authority.restoration_finished(s->authority.context,ticket)||!mp_window(s,ticket)){s->stage=MP_RECOVERY_REQUIRED;return MP_DIRTY;}
 s->dirty=0;s->stage=MP_RESTORED;return FAILED(status)?MP_ROLLED_BACK:MP_OK;
}
MP_RESULT mp_publish(MP_STATE*s,uint64_t ticket){
 if(!mp_live(s))return s==mp_current&&s->ended?MP_ENDED:MP_INVALID;
 if(s->busy||s->management_busy)return MP_BUSY;if(s->stage!=MP_BOUND||s->original_package)return MP_INVALID;
 if(!mp_window(s,ticket)||!mp_identity(s,1)||!mp_window(s,ticket))return MP_DENIED;
 s->busy=1;s->active_window=ticket;MP_RESULT result=MP_IO;uint8_t*strings_pack=0,*changed=0,*update=0,*readback=0;
 UN n=0,fn=0;const uint8_t*f=0;uint16_t maximum=0;size_t written=0;
 s->original_package=mp_export(s,ticket,&s->original_size);
 if(!s->original_package||!mp_package(s->original_package,s->original_size,&f,&fn,&s->previous_max_token)||!mp_original_forms(f,fn)||!get_languages(s,ticket))goto done;
 if(!add_strings(s,ticket))goto done;
 strings_pack=mp_export(s,ticket,&n);
 if(!strings_pack||!mp_package(strings_pack,n,&f,&fn,&maximum)||!mp_original_forms(f,fn)||
  !mp_string_growth_only(s->original_package,s->original_size,strings_pack,n))goto done;
 changed=mp_alloc(s,ticket,fn+45);if(!changed||!w890_security_insert(f,fn,s->tokens,changed,fn+45,&written)||written!=fn+45)goto done;
 s->published_size=n+45;s->published_package=mp_alloc(s,ticket,s->published_size);if(!s->published_package)goto done;
 UN offset=(UN)(f-strings_pack);memcpy(s->published_package,strings_pack,offset);memcpy(s->published_package+offset,changed,written);
 memcpy(s->published_package+offset+written,strings_pack+offset+fn,n-offset-fn);mp_put32(s->published_package+16,(uint32_t)s->published_size);
 update=mp_alloc(s,ticket,written+24);if(!update)goto done;memcpy(update,s->original_package,16);mp_put32(update+16,(uint32_t)written+24);
 memcpy(update+20,changed,written);mp_put32(update+20+written,0xdf000004);
 if(!mp_window(s,ticket)||!mp_identity(s,1)||!mp_window(s,ticket))goto done;
 ES status=s->binding.database->update_list(s->binding.database,s->binding.hii,update);
 if(!mp_window(s,ticket)||FAILED(status))goto done;
 readback=mp_export(s,ticket,&n);
 if(!readback||n!=s->published_size||memcmp(readback,s->published_package,n)||!mp_nonform_equal(strings_pack,n-45,readback,n))goto done;
 for(unsigned i=0;i<6;i++)for(unsigned lang=0;lang<s->language_count;lang++)if(!string_equal(s,ticket,lang,s->tokens[i],texts[i]))goto done;
 if(!mp_identity(s,1)||!mp_window(s,ticket))goto done;
 ap_sha256(changed,written,s->published_forms_sha256);
 if(!s->authority.publication_finished(s->authority.context,ticket,s->tokens,s->published_forms_sha256)||!mp_window(s,ticket))goto done;
 s->stage=MP_PUBLISHED;result=MP_OK;
done:
 mp_free(s,readback);mp_free(s,update);mp_free(s,changed);mp_free(s,strings_pack);
 if(result!=MP_OK&&s->dirty){MP_RESULT restored=restore(s,ticket);result=(restored==MP_OK||restored==MP_ROLLED_BACK)?MP_ROLLED_BACK:restored;}
 if(s->ended)result=MP_ENDED;s->busy=0;return result;
}
MP_RESULT mp_rollback(MP_STATE*s,uint64_t ticket){
 if(!mp_live(s))return s==mp_current&&s->ended?MP_ENDED:MP_INVALID;
 if(s->busy||s->management_busy)return MP_BUSY;
 if(!s->original_package||!s->dirty)return MP_INVALID;
 s->busy=1;s->active_window=ticket;MP_RESULT result=restore(s,ticket);s->busy=0;return result;
}
ES EA mp_native_publish(void*context,uint64_t ticket){return mp_publish(context,ticket)==MP_OK?0:ERR(15);}
MP_RESULT mp_dispose(MP_STATE*s,uint64_t ticket){
 if(!mp_live(s)||!mp_window(s,ticket)||s->busy||s->management_busy||s->dirty||
  (s->stage!=MP_BOUND&&s->stage!=MP_RESTORED)||!mp_identity(s,0)||!mp_window(s,ticket))return MP_DENIED;
 s->active_window=ticket;void*original=s->original_package,*published=s->published_package;s->original_package=0;s->published_package=0;
 mp_free(s,original);mp_free(s,published);
 if(!mp_window(s,ticket)){s->stage=MP_RECOVERY_REQUIRED;return MP_DIRTY;}memset(s,0,sizeof(*s));mp_current=0;return MP_OK;
}
