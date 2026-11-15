/* Non-secret observation only. Called from the existing UNCONFIGURED prompt
 * at application TPL after existing owner checks. No input/variable operations.
 * The six displayed lines checksum only their100B of displayed scalar values,
 * not the complete256B diagnostic record. Unknown fields display FFFFFFFF.
 */
#include "diagnostic_provider.h"
#include "diagnostic_store.h"
#define UNSEEN UINT32_MAX
typedef struct {uint32_t word[25];} DIAG09_DISPLAY;
_Static_assert(sizeof(DIAG09_DISPLAY)==100,"display scalar CRC bytes");
static uint32_t value(const DIAG09_RECORD *r,uint64_t flag,uint32_t n){return r->valid&flag?n:UNSEEN;}
static void words64(uint32_t *out,uint64_t n){out[0]=(uint32_t)n;out[1]=(uint32_t)(n>>32);}
static void display_values(const DIAG09_VIEW *v,DIAG09_DISPLAY *out){
 uint32_t *w=out->word;for(unsigned i=0;i<25;i++)w[i]=UNSEEN;
 words64(w,v->request_valid?v->request.request_serial:0);words64(w+2,v->prompt_count);words64(w+4,v->ack_count);
 if(v->first_valid){w[6]=v->first.hook;w[7]=v->first.reason;w[8]=v->first.detail;w[9]=value(&v->first,D09_V_FRAME,v->first.frame_kind);}
 if(v->request_valid){const DIAG09_RECORD *r=&v->request;
  w[10]=r->hook;w[11]=r->reason;w[12]=r->detail;w[13]=(uint32_t)r->classification;
  w[14]=value(r,D09_V_PAGE,r->page_index);w[15]=value(r,D09_V_FORM,r->form_id);w[16]=value(r,D09_V_PAGE_OWNER,(uint32_t)r->page_owner);w[17]=(uint32_t)r->valid;
  w[18]=value(r,D09_V_FRAME,r->frame_kind);w[19]=value(r,D09_V_CONTROL_TYPE,r->control_type);w[20]=value(r,D09_V_CONTROL_VTABLE,r->control_vtable_rva);
  w[21]=value(r,D09_V_CONTROL_OWNER,r->hii_class);w[22]=value(r,D09_V_CONTROL_OWNER,(uint32_t)r->control_owner);
 }
 w[23]=(v->first_valid?1u:0u)|(v->request_valid?2u:0u);w[24]=v->flags;
}
static void literal(C16 *line,unsigned *at,const char *text){while(*text&&*at<76)line[(*at)++]=(C16)(uint8_t)*text++;}
static void hex(C16 *line,unsigned *at,uint64_t value,unsigned digits){static const char h[]="0123456789ABCDEF";for(unsigned i=digits;i;i--)if(*at<76)line[(*at)++]=(C16)h[(value>>((i-1)*4))&15];}
static void emit(C16 *line,unsigned at){
 if(boot_services_ended||!system_table->out||!system_table->out->out)return;
 line[at++]='\r';line[at++]='\n';line[at]=0;
 system_table->out->out(system_table->out,line);
 /* The next caller/line checks this again; no later service after ending. */
}
static void display_line(const char *prefix,const char *const *names,const uint32_t *values,unsigned count){
 C16 line[80];unsigned at=0;literal(line,&at,prefix);
 for(unsigned i=0;i<count;i++){literal(line,&at,names[i]);hex(line,&at,values[i],8);}emit(line,at);
}
/* External symbol retained for independent exact-PE output verification. */
void diagnostic_render_values(const DIAG09_VIEW *v){
 if(boot_services_ended)return;DIAG09_DISPLAY output;display_values(v,&output);uint32_t *w=output.word;
 C16 line[80];unsigned at=0;literal(line,&at,"D09 R=");hex(line,&at,(uint64_t)w[0]|((uint64_t)w[1]<<32),16);
 literal(line,&at," P=");hex(line,&at,(uint64_t)w[2]|((uint64_t)w[3]<<32),16);literal(line,&at," A=");hex(line,&at,(uint64_t)w[4]|((uint64_t)w[5]<<32),16);emit(line,at);
 const char *f[]={" H="," E="," D="," K="},*r[]={" H="," E="," D="," C="},*p[]={" I="," F="," O="," V="},*c[]={" K="," T="," V="," H="," O="},*s[]={" V="," F="," CRC="};
 display_line("F",f,w+6,4);display_line("R",r,w+10,4);display_line("P",p,w+14,4);display_line("C",c,w+18,5);
 uint32_t last[]={w[23],w[24],d09_crc(w,sizeof(output))};display_line("S",s,last,3);
 ap_secure_zero(&output,sizeof(output));
}
void diagnostic_unconfigured(void){
 if(boot_services_ended)return;DIAG09_VIEW view;
 if(!d09_prompt(split_diagnostic_region(),&view)){memset(&view,0,sizeof(view));view.flags=DIAG09_FLAG_INCOMPLETE;}
 diagnostic_render_values(&view);ap_secure_zero(&view,sizeof(view));
}
void diagnostic_acknowledged(void){if(!boot_services_ended)d09_ack(split_diagnostic_region());}
ES diagnostic_verify_request(void){
 DIAG09_RECORD record;memset(&record,0,sizeof(record));record.hook=D09_INDEPENDENT_VERIFY;record.reason=D09_INDEPENDENT_VERIFY_ACTION;record.classification=-1;record.event_arg=0xffe2;record.event_action=0;record.valid=D09_V_EVENT;
 uint64_t serial=d09_request(split_diagnostic_region(),&record);
 ES status=native_provider.request(&native_provider);
 if(!boot_services_ended)d09_complete(split_diagnostic_region(),serial);
 return status;
}
