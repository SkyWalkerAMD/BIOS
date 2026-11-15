/* Host harness: mocked variables/timer; includes the exact release driver. */
#include "source/driver.c"
ST *gST;REPORT report;char audit[131072];UN audit_len;
static ST st;static BS bs;static RT rt;static PHASE_STATE ph;
static uint8_t mock_setup[SETUP_SIZE],original[SETUP_SIZE];
static TRANSACTION journal;static int present,target,attempts,journal_writes,checks;
static ES write_result,read_result,save_result;static int corrupt_write,delete_fail;
static uint32_t setup_attrs=7;static UN setup_size=SETUP_SIZE;
static int failure_line;
static void ck(int condition,int line){checks++;if(!condition&&!failure_line)failure_line=line;}
#define CHECK(x) ck(!!(x),__LINE__)
void *memcpy(void *d,const void *s,size_t n){uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int c,size_t n){uint8_t *a=d;while(n--)*a++=(uint8_t)c;return d;}
static void strcopy_test(char *d,const char *s){while((*d++=*s++));}
int eq(const void *a,const void *b,size_t n){const uint8_t *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
int same(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
void logtext(const char *s){while(*s&&audit_len<sizeof(audit)-1)audit[audit_len++]=*s++;audit[audit_len]=0;}
void loghex(uint64_t n,unsigned digits){char b[17];for(unsigned i=0;i<digits;i++)b[i]="0123456789ABCDEF"[(n>>((digits-1-i)*4))&15];b[digits]=0;logtext(b);}
void detect_board(void){strcopy_test(report.board,target?"ROG MAXIMUS Z790 HERO":"OTHER");strcopy_test(report.bios,"3107");}
void phase_read(PHASE_STATE *p){*p=ph;}
void phase_log(const PHASE_STATE *p){(void)p;}
static ES EA getvar(C16 *name,GUID *guid,uint32_t *attrs,UN *size,void *data){
 (void)name;
 if(eq(guid,&setup_guid,16)){if(read_result)return read_result;if(*size<setup_size)return ERR(5);*size=setup_size;*attrs=setup_attrs;memcpy(data,mock_setup,SETUP_SIZE);return 0;}
 CHECK(eq(guid,&txn_guid,16));if(!present)return ERR(14);if(*size<sizeof(journal))return ERR(5);*size=sizeof(journal);*attrs=3;memcpy(data,&journal,sizeof(journal));return 0;
}
static ES EA setvar(C16 *name,GUID *guid,uint32_t attrs,UN size,void *data){
 (void)name;
 if(eq(guid,&setup_guid,16)){
  attempts++;CHECK(state==ATTEMPTING&&phase_is(&ph,0));CHECK(size==SETUP_SIZE&&attrs==7);CHECK(present);
  if(write_result)return write_result;
  const uint8_t *p=data;for(unsigned i=1;i<SETUP_SIZE;i++)CHECK(p[i]==mock_setup[i]);
  memcpy(mock_setup,data,size);if(corrupt_write)mock_setup[42]^=1;return 0;
 }
 CHECK(eq(guid,&txn_guid,16));journal_writes++;
 if(!size){CHECK(attrs==0);if(delete_fail)return ERR(8);present=0;return 0;}
 if(save_result)return save_result;
 CHECK(attrs==3&&size==sizeof(journal));memcpy(&journal,data,size);present=1;return 0;
}
static ES EA timer_set(HANDLE h,uint32_t type,uint64_t interval){(void)h;CHECK(type==0||(type==1&&interval==5000000));return 0;}
static void reset(int keep){
 if(!keep){for(unsigned i=0;i<SETUP_SIZE;i++)mock_setup[i]=(uint8_t)(i*13);mock_setup[0]=1;mock_setup[3210]=1;memcpy(original,mock_setup,SETUP_SIZE);present=0;}
 state=IDLE;ticks=unlocked=operation=busy=0;timer=(HANDLE)1;installed_handle=0;attempts=journal_writes=0;
 target=1;write_result=read_result=save_result=0;corrupt_write=delete_fail=0;setup_attrs=7;setup_size=SETUP_SIZE;audit_len=0;
 memset(&ph,0,sizeof(ph));ph.mailbox_attrs=2;ph.mailbox_size=8;ph.mailbox=1;ph.boot_attrs=6;ph.boot_size=1;
 memset(&st,0,sizeof(st));memset(&bs,0,sizeof(bs));memset(&rt,0,sizeof(rt));st.bs=&bs;st.rt=&rt;gST=&st;rt.get_variable=getvar;rt.set_variable=setvar;bs.set_timer=timer_set;
}
static uint32_t crc(void){return probe_crc32(mock_setup,SETUP_SIZE);}
static void fire(unsigned count){for(unsigned i=0;i<count;i++)on_timer(0,0);}
static void run(void){CHECK(queue(1,crc())==0);CHECK(present&&attempts==0);CHECK(depart()==0);ph.mailbox=0;fire(2);}
int run_tests(void){
 reset(0);CHECK(queue(1,crc())==0);ph.mailbox=0;fire(8);CHECK(attempts==0&&state==QUEUED);
 ph.mailbox=1;CHECK(depart()==0);fire(3);CHECK(attempts==0);ph.mailbox=0;fire(1);CHECK(attempts==0);ph.mailbox=1;fire(1);ph.mailbox=0;fire(1);CHECK(attempts==0);fire(1);CHECK(attempts==1&&state==DONE&&mock_setup[0]==0&&present);fire(1000);CHECK(attempts==1);
 reset(1);CHECK(queue(2,crc())==0);CHECK(depart()==0);ph.mailbox=0;fire(2);CHECK(state==DONE&&attempts==1&&!present&&eq(original,mock_setup,SETUP_SIZE));
 reset(0);CHECK(queue(1,crc())==0);CHECK(cancel()==0);ph.mailbox=0;fire(1000);CHECK(attempts==0&&present&&state==CANCELLED);
 reset(1);CHECK(queue(2,crc())==0);CHECK(state==DONE&&attempts==0&&!present);
 reset(0);CHECK(queue(1,crc())==0);CHECK(depart()==0);fire(600);ph.mailbox=0;fire(20);CHECK(attempts==0&&state==TIMED_OUT&&present);
 reset(0);CHECK(queue(1,crc())==0);CHECK(depart()==0);CHECK(resume()==0);ph.mailbox=0;fire(3);CHECK(attempts==0&&state==CANCELLED);
 reset(0);target=0;CHECK(queue(1,crc())==ERR(15)&&!present);reset(0);CHECK(queue(3,crc())==ERR(15));
 reset(0);CHECK(queue(1,crc()^1)==ERR(15)&&!present);reset(0);setup_attrs=3;CHECK(FAILED(queue(1,crc()))&&!present);
 reset(0);setup_size=SETUP_SIZE-1;CHECK(FAILED(queue(1,crc()))&&!present);reset(0);mock_setup[3210]=0;CHECK(FAILED(queue(1,crc()))&&!present);
 reset(0);mock_setup[0]=2;CHECK(FAILED(queue(1,crc()))&&!present);reset(0);ph.mailbox=0;CHECK(FAILED(queue(1,crc()))&&!present);
 reset(0);save_result=ERR(8);CHECK(queue(1,crc())==ERR(8)&&!present&&attempts==0);
 reset(0);CHECK(queue(1,crc())==0);CHECK(queue(1,crc())==ERR(15));CHECK(depart()==0);mock_setup[200]^=1;ph.mailbox=0;fire(2);CHECK(attempts==0&&state==FAILED_STATE&&present);
 reset(0);CHECK(queue(1,crc())==0);CHECK(depart()==0);journal.checksum^=1;ph.mailbox=0;fire(2);CHECK(attempts==0&&state==FAILED_STATE);
 reset(0);write_result=ERR(26);run();CHECK(state==FAILED_STATE&&attempts==1&&present&&eq(mock_setup,original,SETUP_SIZE));fire(10);CHECK(attempts==1);
 reset(0);corrupt_write=1;run();CHECK(state==FAILED_STATE&&attempts==1&&present);reset(1);CHECK(queue(2,crc())==ERR(15)&&present&&attempts==0);
 reset(0);run();reset(1);delete_fail=1;CHECK(queue(2,crc())==0);CHECK(depart()==0);ph.mailbox=0;fire(2);CHECK(state==FAILED_STATE&&present&&eq(mock_setup,original,SETUP_SIZE));
 reset(1);CHECK(queue(2,crc())==0&&!present&&attempts==0);
 reset(0);CHECK(queue(1,crc())==0);CHECK(depart()==0);ph.mailbox=0;ph.mailbox_attrs=3;fire(5);CHECK(attempts==0);ph.mailbox_attrs=2;ph.boot_status=ERR(14);fire(5);CHECK(attempts==0);ph.boot_status=0;ph.boot_phase=1;fire(5);CHECK(attempts==0);
 return failure_line;
}
int get_checks(void){return checks;}
