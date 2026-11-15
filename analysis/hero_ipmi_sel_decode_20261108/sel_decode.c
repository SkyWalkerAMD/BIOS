/* Standard SEL record presentation, with no I/O, allocation or libc dependency.
 * Field layout: EDK2 edk2-stable202502 IpmiNetFnStorage.h.
 * Standard event classifications: IPMI tables 42-1/42-2/42-3, cross-checked
 * against the pinned pyghmi 1.6.19 source. No OEM payload interpretation.
 */
#include "sel_decode.h"
typedef struct {char *out;size_t cap,used;int truncated;} TEXT;
static const char hex[]="0123456789ABCDEF";
static void put(TEXT *t,char c){
 if(t->used+1<t->cap)t->out[t->used++]=c;else t->truncated=1;
}
static void text(TEXT *t,const char *s){while(*s)put(t,*s++);}
static void hx(TEXT *t,uint32_t n,unsigned width){
 for(unsigned i=width;i;i--)put(t,hex[(n>>((i-1)*4))&15]);
}
static void dec(TEXT *t,uint32_t n,unsigned width){
 char s[10];unsigned i=0;do{s[i++]=(char)('0'+n%10);n/=10;}while(n);
 while(width>i){put(t,'0');width--;}
 while(i)put(t,s[--i]);
}
static uint32_t le32(const uint8_t *p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static int leap(unsigned y){return y%4==0&&(y%100!=0||y%400==0);}
static void stamp(TEXT *t,uint32_t n){
 if(n==0xffffffffU){text(t,"TIME?");return;}
 /* IPMI's pre-initialization range is not a 1970-based calendar date. */
 if(n<0x20000000U){text(t,"PRE+");dec(t,n,0);put(t,'s');return;}
 unsigned days=n/86400U,sec=n%86400U,year=1970,month=0;
 static const unsigned char md[]={31,28,31,30,31,30,31,31,30,31,30,31};
 while(days>=365U+(unsigned)leap(year)){days-=365U+(unsigned)leap(year);year++;}
 while(days>=(unsigned)md[month]+(unsigned)(month==1&&leap(year))){days-=(unsigned)md[month]+(unsigned)(month==1&&leap(year));month++;}
 /* Stored BMC calendar, not a claim about UTC, local timezone or corrected
  * historical time. The exact timestamp remains in the raw record. */
 text(t,"BMC@");dec(t,year,4);put(t,'-');dec(t,month+1,2);put(t,'-');dec(t,days+1,2);
 put(t,' ');dec(t,sec/3600U,2);put(t,':');dec(t,sec/60U%60U,2);put(t,':');dec(t,sec%60U,2);
}
static const char *sensor_name(unsigned type){
 switch(type){
 case 1:return "Temp";case 2:return "Voltage";case 3:return "Current";case 4:return "Fan";
 case 7:return "CPU";case 8:return "PSU";case 9:return "PowerUnit";case 0xc:return "Memory";
 case 0xf:return "Firmware";case 0x10:return "EventLog";case 0x12:return "System";
 case 0x1d:return "Boot";case 0x1e:return "BootError";case 0x1f:return "OSBoot";
 case 0x20:return "OSStop";case 0x22:return "ACPI";case 0x23:return "Watchdog2";
 case 0x27:return "LAN";case 0x28:return "MgmtHealth";case 0x29:return "Battery";
 case 0x2b:return "Version";case 0x2c:return "FRU";default:return "Sensor";
 }
}
/* These are state/event labels. ASSERT/DEASSERT is presented separately;
 * neither direction alone is a health verdict, and deassertion of presence
 * must not be relabeled as a recovery. Event Data2/3 are not guessed. */
static const char *description(unsigned type,unsigned event,unsigned offset){
 static const char *const threshold[]={"Lower NC falling","Lower NC rising","Lower critical falling","Lower critical rising",
  "Lower NR falling","Lower NR rising","Upper NC falling","Upper NC rising","Upper critical falling","Upper critical rising","Upper NR falling","Upper NR rising"};
 static const char *const psu[]={"Presence","Failure","Predictive failure","Input lost","Input lost/out-of-range","Input out-of-range","Config error","Inactive"};
 static const char *const version[]={"HW change","FW/SW change","HW incompatible","FW/SW incompatible",
  "HW revision invalid/unsupported","FW/SW version invalid/unsupported","HW change succeeded","FW/SW change succeeded"};
 if(event==1)return offset<12?threshold[offset]:"Unknown threshold";
 if(event==2){static const char *const a[]={"Idle","Active","Busy"};return offset<3?a[offset]:"Unknown generic";}
 if(event==3){static const char *const a[]={"State deasserted","State asserted"};return offset<2?a[offset]:"Unknown generic";}
 if(event==0x6f){
  if(type==8&&offset<8)return psu[offset];
  if(type==0x2b&&offset<8)return version[offset];
  if(type==0x23){switch(offset){case 0:return "Expired";case 1:return "Hard reset";case 2:return "Power down";case 3:return "Power cycle";case 8:return "Timer interrupt";}}
  return "Sensor-specific";
 }
 if(event>=2&&event<=0xc)return "Generic discrete";
 return "Unknown event";
}
static void raw(TEXT *t,const uint8_t *r){text(t," | ");for(unsigned i=0;i<16;i++)hx(t,r[i],2);}
int sel_format_record(char *out,size_t cap,const uint8_t *r,size_t len){
 if(!out||!cap)return SEL_FORMAT_INVALID;
 TEXT t={out,cap,0,0};out[0]=0;
 if(!r||len!=16){text(&t,"Invalid SEL record");out[t.used]=0;return SEL_FORMAT_INVALID;}
 unsigned id=(unsigned)r[0]|((unsigned)r[1]<<8),kind=r[2];
 if(kind==2){
  text(&t,"SYS #");hx(&t,id,4);put(&t,' ');stamp(&t,le32(r+3));put(&t,' ');
  if(r[9]!=4){text(&t,"EvM=");hx(&t,r[9],2);text(&t," unsupported");}
  else{
   text(&t,sensor_name(r[10]));put(&t,'(');hx(&t,r[10],2);text(&t,")#");hx(&t,r[11],2);
   text(&t,(r[12]&0x80)?" DEASSERT ":" ASSERT ");
   unsigned event=r[12]&0x7f,offset=r[13]&15;
   text(&t,"E=");hx(&t,event,2);
   /* An OEM event type retains direction and raw bytes, but its data is not
    * assigned a standard offset or standard sensor-specific description. */
   if(event>=0x70){text(&t," OEM data");}
   else if(event==1||(event>=2&&event<=0xc)||event==0x6f){
    put(&t,'/');hx(&t,offset,1);put(&t,' ');text(&t,description(r[10],event,offset));
   }else text(&t," Reserved/unspecified");
  }
 }else if(kind>=0xc0&&kind<=0xdf){
  text(&t,"OEM-T ");hx(&t,kind,2);text(&t," #");hx(&t,id,4);put(&t,' ');stamp(&t,le32(r+3));
  text(&t," MFG=");hx(&t,(uint32_t)r[7]|((uint32_t)r[8]<<8)|((uint32_t)r[9]<<16),6);
 }else if(kind>=0xe0){
  text(&t,"OEM-N ");hx(&t,kind,2);text(&t," #");hx(&t,id,4);text(&t," no timestamp");
 }else{
  text(&t,"UNKNOWN type=");hx(&t,kind,2);text(&t," #");hx(&t,id,4);
 }
 raw(&t,r);out[t.used]=0;
 return t.truncated?SEL_FORMAT_TRUNCATED:SEL_FORMAT_OK;
}
