#include "p1.h"
REPORT report;
void strcopy(char *d,size_t cap,const char *s){size_t i=0;if(!cap)return;while(i+1<cap&&s[i]){d[i]=s[i];i++;}d[i]=0;}
void result(const char *s){strcopy(report.result,sizeof(report.result),s);logtext("RESULT: ");logtext(s);logtext("\r\n");}
/* Only the bounded exact UUID/board/BIOS identity gate supplies these names.
 * No unbounded second walk of firmware-owned SMBIOS memory is used. */
void detect_board(void){
 report.board[0]=report.bios[0]=0;
 if(identity_check()==0){strcopy(report.board,sizeof(report.board),"ROG MAXIMUS Z790 HERO");strcopy(report.bios,sizeof(report.bios),"3107");}
}
/* Safe-default preflight permits only keep-current/channel0. No settings writer
 * is linked and no P6 settings entry point is called by this application. */
unsigned p6_selected_lan(void){return 0;}
static unsigned trace_count;
typedef struct {const char *name;unsigned starts,ends,nonzero;} TRACE;
static TRACE traces[16];static unsigned trace_used;
static const char *last_start="none",*last_end="none";static UN last_a,last_b,last_c,last_n;static ES last_status;
static TRACE *slot(const char *name){for(unsigned i=0;i<trace_used;i++)if(same(name,traces[i].name))return traces+i;if(trace_used<16){traces[trace_used].name=name;return traces+trace_used++;}return 0;}
static char trace_summary[4096];static unsigned summary_len;
static void sa(const char *s){while(*s&&summary_len+1<sizeof(trace_summary))trace_summary[summary_len++]=*s++;trace_summary[summary_len]=0;}
static void sh(UN n){char b[17];for(unsigned i=0;i<16;i++)b[i]="0123456789ABCDEF"[(n>>((15-i)*4))&15];b[16]=0;sa(b);}
const char *a1_trace_summary(void){
 summary_len=0;sa("BEGIN HII CALL SUMMARY (counts and numbers are hex)\r\n");
 for(unsigned i=0;i<trace_used;i++){TRACE *t=traces+i;sa(t->name);sa(" before=");sh(t->starts);sa(" after=");sh(t->ends);sa(" nonzero_status=");sh(t->nonzero);sa("\r\n");}
 sa("LAST_STARTED=");sa(last_start);sa(" a=");sh(last_a);sa(" b=");sh(last_b);sa(" c=");sh(last_c);sa("\r\n");
 sa("LAST_COMPLETED=");sa(last_end);sa(" status=");sh(last_status);sa(" n=");sh(last_n);sa("\r\nEND HII CALL SUMMARY\r\n");return trace_summary;
}
static void trace_number(UN v){
 char b[17];unsigned start=15;b[16]=0;for(int i=15;i>=0;i--){b[i]="0123456789ABCDEF"[v&15];v>>=4;if(b[i]!='0')start=(unsigned)i;}
 logtext(b+start);say(b+start);
}
int a1_before(const char *name,UN a,UN b,UN c){
 if(audit_bad||audit_len>sizeof(audit)-8192||trace_count>=12000){audit_bad=1;say("TRACE CAPACITY EXHAUSTED; stage stops.\r\n");return 0;}
 TRACE *t=slot(name);if(t)t->starts++;last_start=name;last_a=a;last_b=b;last_c=c;
 /* This is an application-level diagnostic, never a timer or notify callback. */
 logtext("> ");logtext(name);say("ENTER ");say(name);logtext(" #");say(" #");trace_number(++trace_count);
 logtext(" a=");say(" a=");trace_number(a);logtext(" b=");say(" b=");trace_number(b);logtext(" c=");say(" c=");trace_number(c);logtext("\r\n");say("\r\n");return 1;
}
void a1_after(const char *name,ES e,UN n){TRACE *t=slot(name);if(t){t->ends++;t->nonzero+=e!=0;}last_end=name;last_status=e;last_n=n;logtext("< ");logtext(name);logtext(" status=");loghex(e,16);logtext(" n=");loghex(n,16);logtext("\r\n");}
