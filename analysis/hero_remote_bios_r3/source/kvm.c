/* Display-only transport. No filesystem, network, NVRAM, or SPI operations. */
#include "kvm.h"

#include "vendor/qrcodegen.h"
#include <string.h>
#define CHUNK 512U
#define QRBUF qrcodegen_BUFFER_LEN_FOR_VERSION(30)
typedef struct { uint16_t scan,unicode; } KKEY;
typedef struct INPUT INPUT;
struct INPUT { void *reset; ES (EA *read)(INPUT *,KKEY *); void *event; };
typedef struct { int32_t max_mode,mode,attribute,column,row; uint8_t visible; } KTEXTMODE;
typedef struct TEXT TEXT;
struct TEXT { void *reset; ES(EA *out)(TEXT *,C16 *); void *test;
 ES(EA *query)(TEXT *,UN,UN *,UN *);void *set_mode;ES(EA *attribute)(TEXT *,UN);
 ES(EA *clear)(TEXT *);void *cursor;ES(EA *visible)(TEXT *,uint8_t);KTEXTMODE *mode; };
typedef struct { uint32_t version,width,height,format,masks[4],stride; } GINFO;
typedef struct { uint32_t maximum,current;GINFO *info;UN info_size;uint64_t framebuffer;UN framebuffer_size; } GMODE;
typedef struct GOP GOP;
struct GOP {ES(EA *query)(GOP *,uint32_t,UN *,GINFO **);void *set_mode;
 ES(EA *blt)(GOP *,uint32_t *,uint32_t,UN,UN,UN,UN,UN,UN,UN);GMODE *mode;};
OFF(TEXT,mode,72);OFF(INPUT,event,16);OFF(GOP,mode,24);OFF(GMODE,info,8);OFF(GINFO,stride,32);
static GUID gop_guid={0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
static uint8_t qr[QRBUF],scratch[QRBUF];
static uint32_t text_starts[131073];
static ST *table;static TEXT *out;static GOP *gop;static uint32_t *pixels;
static unsigned width,height,columns,body_rows;
static const char *content;static size_t total;static uint32_t checksum;

uint32_t probe_crc32(const void *data,size_t n){
 const uint8_t *p=data;uint32_t crc=0xffffffffU;
 while(n--){crc^=*p++;for(unsigned k=0;k<8;k++)crc=(crc>>1)^(0xedb88320U & (0U-(crc&1)));}
 return ~crc;
}
void *memmove(void *dest,const void *src,size_t n){uint8_t *d=dest;const uint8_t *s=src;
 if((uintptr_t)d<(uintptr_t)s){for(size_t i=0;i<n;i++)d[i]=s[i];}else{while(n){n--;d[n]=s[n];}}return dest;}
size_t strlen(const char *s){size_t n=0;while(s[n])n++;return n;}
char *strchr(const char *s,int c){do{if(*s==(char)c)return (char *)s;}while(*s++);return 0;}
static void print_n(const char *s,size_t n){if(!out||!out->out)return;C16 b[160];
 while(n){size_t k=n<159?n:159;for(size_t i=0;i<k;i++)b[i]=(uint8_t)s[i];b[k]=0;out->out(out,b);s+=k;n-=k;}}
static void print(const char *s){print_n(s,strlen(s));}
typedef struct {char *p;size_t n,cap;int bad;} STR;
static void add(STR *s,const char *v){while(*v){if(s->n+1<s->cap)s->p[s->n++]=*v;else s->bad=1;v++;}if(s->cap)s->p[s->n]=0;}
static void dec(STR *s,uint32_t n){char b[11];unsigned i=10;b[i]=0;do{b[--i]=(char)('0'+n%10);n/=10;}while(n);add(s,b+i);}
static void hex32(STR *s,uint32_t n){char b[9];const char *h="0123456789ABCDEF";for(unsigned i=0;i<8;i++)b[i]=h[(n>>((7-i)*4))&15];b[8]=0;add(s,b);}

size_t kvm_make_frame(const uint8_t *data,size_t len,unsigned page,uint8_t *dest,size_t cap){
 if(!data||!dest||!len||len>131072||page>=(len+CHUNK-1)/CHUNK)return 0;
 size_t off=(size_t)page*CHUNK,n=len-off;if(n>CHUNK)n=CHUNK;
 char h[160];STR s={h,0,sizeof(h),0};add(&s,"HERO-REMOTE-BIOS-R3-QR1\nT=");dec(&s,(uint32_t)len);
 add(&s,";C=");hex32(&s,probe_crc32(data,len));add(&s,";P=");dec(&s,page+1);add(&s,"/");dec(&s,(uint32_t)((len+CHUNK-1)/CHUNK));
 add(&s,";O=");dec(&s,(uint32_t)off);add(&s,";N=");dec(&s,(uint32_t)n);
 add(&s,";D=");hex32(&s,probe_crc32(data+off,n));add(&s,"\n\n");
 if(s.bad||s.n+n>cap)return 0;memcpy(dest,h,s.n);memcpy(dest+s.n,data+off,n);return s.n+n;
}
int kvm_encode_frame(const uint8_t *data,size_t len,unsigned page,uint8_t *result,uint8_t *temp){
 size_t n=kvm_make_frame(data,len,page,temp,QRBUF);if(!n)return 0;
 return qrcodegen_encodeBinary(temp,n,result,qrcodegen_Ecc_MEDIUM,1,30,qrcodegen_Mask_AUTO,true);
}

/* Compact original 5x7 uppercase/digit font, stored as row masks. */
static const uint8_t font[36][7]={
 {14,17,19,21,25,17,14},{4,12,4,4,4,4,14},{14,17,1,2,4,8,31},{30,1,1,14,1,1,30},
 {2,6,10,18,31,2,2},{31,16,16,30,1,1,30},{14,16,16,30,17,17,14},{31,1,2,4,8,8,8},
 {14,17,17,14,17,17,14},{14,17,17,15,1,1,14},
 {14,17,17,31,17,17,17},{30,17,17,30,17,17,30},{14,17,16,16,16,17,14},
 {30,17,17,17,17,17,30},{31,16,16,30,16,16,31},{31,16,16,30,16,16,16},
 {14,17,16,23,17,17,15},{17,17,17,31,17,17,17},{14,4,4,4,4,4,14},
 {7,2,2,2,18,18,12},{17,18,20,24,20,18,17},{16,16,16,16,16,16,31},
 {17,27,21,21,17,17,17},{17,25,21,19,17,17,17},{14,17,17,17,17,17,14},
 {30,17,17,30,16,16,16},{14,17,17,17,21,18,13},{30,17,17,30,20,18,17},
 {15,16,16,14,1,1,30},{31,4,4,4,4,4,4},{17,17,17,17,17,17,14},
 {17,17,17,17,17,10,4},{17,17,17,21,21,21,10},{17,17,10,4,10,17,17},
 {17,17,10,4,4,4,4},{31,1,2,4,8,16,31}};
static void rect(unsigned x,unsigned y,unsigned w,unsigned h,uint32_t color){
 if(!pixels||x>=width||y>=height)return;if(w>width-x)w=width-x;if(h>height-y)h=height-y;
 for(unsigned j=0;j<h;j++)for(unsigned i=0;i<w;i++)pixels[(size_t)(y+j)*width+x+i]=color;
}
static void label(unsigned x,unsigned y,const char *s,unsigned scale){
 for(;*s;s++,x+=6*scale){unsigned ch=(uint8_t)*s;if(ch>='a'&&ch<='z')ch-=32;
 const uint8_t *rows=ch>='0'&&ch<='9'?font[ch-'0']:(ch>='A'&&ch<='Z'?font[ch-'A'+10]:0);
 for(unsigned j=0;j<7;j++){unsigned bits=rows?rows[j]:0;
  if(ch=='/'&&j<5)bits=1U<<j;if(ch=='-'&&j==3)bits=31;
  if(ch==':'&&(j==2||j==5))bits=4;if(ch=='.'&&j==6)bits=4;
  if(ch=='='&&(j==2||j==4))bits=31;
  for(unsigned i=0;i<5;i++)if(bits&(1U<<(4-i)))rect(x+i*scale,y+j*scale,scale,scale,0);
 }}
}
static void title(char *s,size_t cap,const char *mode,unsigned page,unsigned count){
 STR b={s,0,cap,0};add(&b,mode);add(&b," PAGE ");dec(&b,page+1);add(&b,"/");dec(&b,count);
 add(&b,"  BYTES ");dec(&b,(uint32_t)total);add(&b,"  CRC ");hex32(&b,checksum);
}
static int graphics(void){
 void *p=0;ES e=table->bs->handle_protocol(table->out_handle,&gop_guid,&p);
 if(FAILED(e)||!p){p=0;e=table->bs->locate_protocol(&gop_guid,0,&p);}
 if(FAILED(e)||!p)return 0;gop=p;
 if(!gop->blt||!gop->mode)return 0;
 GMODE *mode=gop->mode;
 if(mode->info&&mode->info_size>=sizeof(GINFO)){
  width=mode->info->width;height=mode->info->height;
 }else{
  /* HERO's console GOP exposes InfoSize=0, although QueryMode(current)
   * succeeds. Query that same GOP; do not switch display interfaces or
   * repair firmware-owned Mode/Info fields in place. */
  if(!gop->query||!mode->maximum||mode->current>=mode->maximum)return 0;
  GINFO *info=0;UN size=0;
  e=gop->query(gop,mode->current,&size,&info);
  if(info==mode->info&&info)return 0;
  int valid=!FAILED(e)&&info&&size>=sizeof(GINFO);
  if(valid){width=info->width;height=info->height;}
  /* QueryMode owns a fresh pool allocation under the UEFI contract. Never
   * free a returned alias of the GOP's borrowed live Mode.Info pointer. */
  if(info&&FAILED(table->bs->free_pool(info)))return 0;
  if(!valid)return 0;
 }
 if(width<640||height<480||width>4096||height>2160)return 0;
 e=table->bs->allocate_pool(4,(UN)width*height*4,(void **)&pixels);
 return !FAILED(e)&&pixels;
}
static int qr_page(unsigned page,unsigned count,unsigned warnings){
 if(!pixels||!kvm_encode_frame((const uint8_t *)content,total,page,qr,scratch))return 0;
 unsigned size=(unsigned)qrcodegen_getSize(qr)+8,scale=(height-120)/size;
 if(scale>(width-40)/size)scale=(width-40)/size;if(scale>6)scale=6;if(scale<2)return 0;
 for(size_t i=0;i<(size_t)width*height;i++)pixels[i]=0x00ffffff;
 char line[120];title(line,sizeof(line),"QR",page,count);
 print(line);print("\r\n");
 label(20,16,"HERO Remote BIOS R3 - KVM LOG",2);label(20,42,line,2);
 label(20,66,warnings?"PARTIAL SNAPSHOT - DIAGNOSTIC ONLY":"RAM LOG SNAPSHOT - CAPTURE ALL PAGES",1);
 unsigned qx=(width-size*scale)/2,qy=78;
 for(unsigned y=0;y<size-8;y++)for(unsigned x=0;x<size-8;x++)
  if(qrcodegen_getModule(qr,(int)x,(int)y))rect(qx+(x+4)*scale,qy+(y+4)*scale,scale,scale,0);
 label(20,height-42,"N/ENTER: NEXT   P: PREVIOUS   T: TEXT   ESC: EXIT",2);
 label(20,height-18,page+1==count?"LAST PAGE - CAPTURE ALL PAGES BEFORE EXIT":"SAVE A CLEAR SCREENSHOT OF EVERY QR PAGE",1);
 return !FAILED(gop->blt(gop,pixels,2,0,0,0,0,width,height,(UN)width*4));
}
static size_t text_end(size_t start,char *render){
 size_t pos=start,n=0;unsigned row=0,col=0;
 while(pos<total&&row<body_rows){char c=content[pos++];if(c=='\r')continue;
  if(c=='\n'){if(render){render[n]='\r';render[n+1]='\n';}n+=2;row++;col=0;continue;}
  if(render)render[n]=c;n++;col++;
  if(col==columns){if(render){render[n]='\r';render[n+1]='\n';}n+=2;row++;col=0;}
 }
 if(render)render[n]=0;return pos;
}
static void text_page(unsigned page,unsigned count,int forced){
 if(out->attribute)out->attribute(out,7);if(out->clear)out->clear(out);
 char line[120];static char body[4096];title(line,sizeof(line),"TEXT",page,count);
 print("HERO Remote BIOS R3 KVM - log capture\r\n");print(line);print("\r\n");
 print(forced?"N/ENTER: next  P: previous  ESC: exit\r\n\r\n":"N/ENTER: next  P: previous  Q: QR  ESC: exit\r\n\r\n");
 text_end(text_starts[page],body);print(body);
 print("\r\nEND TEXT PAGE - QR MODE PRESERVES EXACT LOG BYTES\r\n");
}
static ES key(INPUT *input,KKEY *key){
 for(;;){ES e=input->read(input,key);if(e!=ERR(6))return e;
  if(table->bs->wait_for_event&&input->event){typedef ES(EA *WAIT)(UN,void **,UN *);
   UN index=0;e=((WAIT)table->bs->wait_for_event)(1,&input->event,&index);if(FAILED(e))return e;
  }else table->bs->stall(50000);
 }
}
ES kvm_present(ST *st,const char *data,size_t len,unsigned warnings){
 table=st;out=(TEXT *)st->out;INPUT *input=(INPUT *)st->in;content=data;total=len;pixels=0;gop=0;
 if(!out||!out->out||!input||!input->read||!len||len>131072)return ERR(3);
 checksum=probe_crc32(data,len);
 print("KVM_LOG_BEGIN\r\n");print_n(data,len);print("KVM_LOG_END\r\n");
 UN c=80,r=25;if(out->query&&out->mode&&out->mode->mode>=0){
  UN tc=0,tr=0;if(!FAILED(out->query(out,(UN)out->mode->mode,&tc,&tr))&&tc>=40&&tr>=12){c=tc;r=tr;}}
 columns=(unsigned)(c>120?119:c-1);body_rows=(unsigned)(r>32?24:r-8);
 unsigned text_count=0;size_t pos=0;
 while(pos<len&&text_count<131072){text_starts[text_count++]=(uint32_t)pos;size_t end=text_end(pos,0);if(end<=pos)return ERR(7);pos=end;}
 unsigned qr_count=(unsigned)((len+CHUNK-1)/CHUNK),page=0;int use_qr=(warnings&2)?0:graphics();
 uint8_t cursor=out->mode?out->mode->visible:1;if(out->visible)out->visible(out,0);
 ES result=0;
 for(;;){
  if(use_qr&&!qr_page(page,qr_count,warnings&1)){use_qr=0;page=0;}
  if(!use_qr)text_page(page,text_count,(warnings&2)!=0);
  KKEY k={0,0};result=key(input,&k);if(FAILED(result))break;
  if(k.scan==0x17||k.unicode==27)break;
  unsigned count=use_qr?qr_count:text_count;
  if(k.unicode=='n'||k.unicode=='N'||k.unicode==13||k.unicode==32||k.scan==3||k.scan==0xa){if(page+1<count)page++;}
  else if(k.unicode=='p'||k.unicode=='P'||k.scan==4||k.scan==9){if(page)page--;}
  else if(k.unicode=='t'||k.unicode=='T'){use_qr=0;page=0;}
  else if((k.unicode=='q'||k.unicode=='Q')&&pixels){use_qr=1;page=0;}
  else if(k.scan==5)page=0;else if(k.scan==6)page=count-1;
 }
 if(pixels){table->bs->free_pool(pixels);pixels=0;}
 if(out->attribute)out->attribute(out,7);if(out->clear)out->clear(out);if(out->visible)out->visible(out,cursor);
 print("R3 log viewer closed. Captures must be saved on your computer.\r\n");
 return result;
}
