/* Bounded JSON reader: 32 KiB, 2048 tokens, depth 12, duplicate-key rejection.
 * String comparison decodes validated UTF-8 / Unicode escapes; no allocation. */
#define CJ_MAX 2048u
typedef struct {uint32_t begin,end,after;char kind;} CJ_TOKEN;
typedef struct {const char *text;uint32_t bytes,pos,count;CJ_TOKEN tokens[CJ_MAX];} CJ;
static int cj_hex(unsigned c){return c>='0'&&c<='9'?(int)c-'0':c>='a'&&c<='f'?(int)c-'a'+10:c>='A'&&c<='F'?(int)c-'A'+10:-1;}
static int cj_hex4(const char *s,uint32_t end,uint32_t *p){
 if(end-*p<4)return -1;unsigned v=0;
 for(unsigned i=0;i<4;i++){int n=cj_hex((uint8_t)s[(*p)++]);if(n<0)return -1;v=(v<<4)|(unsigned)n;}return (int)v;
}
static int cj_char(const char *s,uint32_t end,uint32_t *p){
 if(*p>=end)return -1;unsigned c=(uint8_t)s[(*p)++];
 if(c=='\\'){
  if(*p>=end)return -1;c=(uint8_t)s[(*p)++];
  if(c=='"'||c=='\\'||c=='/')return (int)c;
  if(c=='b')return 8;if(c=='f')return 12;if(c=='n')return 10;if(c=='r')return 13;if(c=='t')return 9;
  if(c!='u')return -1;int h=cj_hex4(s,end,p);if(h<0)return -1;
  if(h>=0xdc00&&h<=0xdfff)return -1;
  if(h>=0xd800&&h<=0xdbff){
   if(end-*p<6||s[(*p)++]!='\\'||s[(*p)++]!='u')return -1;
   int l=cj_hex4(s,end,p);if(l<0xdc00||l>0xdfff)return -1;
   return 0x10000+((h-0xd800)<<10)+(l-0xdc00);
  }return h;
 }
 if(c<32)return -1;if(c<128)return (int)c;
 unsigned n=0,v=0,min=0;
 if(c>=0xc2&&c<=0xdf){n=1;v=c&31;min=0x80;}
 else if(c>=0xe0&&c<=0xef){n=2;v=c&15;min=0x800;}
 else if(c>=0xf0&&c<=0xf4){n=3;v=c&7;min=0x10000;}else return -1;
 if(end-*p<n)return -1;
 for(unsigned i=0;i<n;i++){c=(uint8_t)s[(*p)++];if((c&0xc0)!=0x80)return -1;v=(v<<6)|(c&63);}
 return v<min||v>0x10ffff||(v>=0xd800&&v<=0xdfff)?-1:(int)v;
}
static int cj_strings(const CJ *a,unsigned x,const CJ *b,unsigned y,int fold){
 if(x>=a->count||y>=b->count||a->tokens[x].kind!='s'||b->tokens[y].kind!='s')return 0;
 uint32_t p=a->tokens[x].begin,q=b->tokens[y].begin;
 while(p<a->tokens[x].end&&q<b->tokens[y].end){
  int c=cj_char(a->text,a->tokens[x].end,&p),d=cj_char(b->text,b->tokens[y].end,&q);
  if(c<0||d<0)return 0;if(fold){if(c>='A'&&c<='Z')c+=32;if(d>='A'&&d<='Z')d+=32;}if(c!=d)return 0;
 }return p==a->tokens[x].end&&q==b->tokens[y].end;
}
static int cj_is(const CJ *j,unsigned t,const char *s){
 if(t>=j->count||j->tokens[t].kind!='s')return 0;uint32_t p=j->tokens[t].begin,i=0;
 while(p<j->tokens[t].end){int c=cj_char(j->text,j->tokens[t].end,&p);if(c<0||!s[i]||c!=(uint8_t)s[i++])return 0;}return !s[i];
}
static void cj_space(CJ *j){while(j->pos<j->bytes&&(j->text[j->pos]==' '||j->text[j->pos]=='\t'||j->text[j->pos]=='\r'||j->text[j->pos]=='\n'))j->pos++;}
static int cj_value(CJ *j,unsigned depth){
 cj_space(j);if(j->pos==j->bytes||j->count==CJ_MAX||depth>12)return 0;
 unsigned id=j->count++;CJ_TOKEN *t=&j->tokens[id];t->begin=j->pos;t->kind=j->text[j->pos++];
 if(t->kind=='"'){
  t->kind='s';t->begin=j->pos;
  while(j->pos<j->bytes&&j->text[j->pos]!='"')if(cj_char(j->text,j->bytes,&j->pos)<0)return 0;
  if(j->pos==j->bytes)return 0;t->end=j->pos++;
 }else if(t->kind=='{'||t->kind=='['){
  char close=t->kind=='{'?'}':']';cj_space(j);
  if(j->pos<j->bytes&&j->text[j->pos]==close)j->pos++;
  else for(;;){
   if(t->kind=='{'){
    unsigned key=j->count;if(j->pos==j->bytes||j->text[j->pos]!='"'||!cj_value(j,depth+1))return 0;
    for(unsigned prev=id+1;prev<key;prev=j->tokens[prev+1].after)if(cj_strings(j,key,j,prev,0))return 0;
    cj_space(j);if(j->pos==j->bytes||j->text[j->pos++]!=':')return 0;
   }
   if(!cj_value(j,depth+1))return 0;cj_space(j);if(j->pos==j->bytes)return 0;
   if(j->text[j->pos]==close){j->pos++;break;}if(j->text[j->pos++]!=',')return 0;cj_space(j);
  }t->end=j->pos;
 }else{
  j->pos=t->begin;
  if(t->kind=='t'||t->kind=='f'||t->kind=='n'){
   const char *word=t->kind=='t'?"true":t->kind=='f'?"false":"null";unsigned n=t->kind=='f'?5:4;
   if(j->bytes-j->pos<n||!cr_eq(j->text+j->pos,word,n))return 0;j->pos+=n;
  }else{
   t->kind='d';if(j->text[j->pos]=='-')j->pos++;if(j->pos==j->bytes)return 0;
   if(j->text[j->pos]=='0')j->pos++;else{if(j->text[j->pos]<'1'||j->text[j->pos]>'9')return 0;while(j->pos<j->bytes&&j->text[j->pos]>='0'&&j->text[j->pos]<='9')j->pos++;}
   if(j->pos<j->bytes&&j->text[j->pos]=='.'){unsigned p=++j->pos;while(j->pos<j->bytes&&j->text[j->pos]>='0'&&j->text[j->pos]<='9')j->pos++;if(p==j->pos)return 0;}
   if(j->pos<j->bytes&&(j->text[j->pos]=='e'||j->text[j->pos]=='E')){j->pos++;if(j->pos<j->bytes&&(j->text[j->pos]=='+'||j->text[j->pos]=='-'))j->pos++;unsigned p=j->pos;while(j->pos<j->bytes&&j->text[j->pos]>='0'&&j->text[j->pos]<='9')j->pos++;if(p==j->pos)return 0;}
  }t->end=j->pos;
 }t->after=j->count;return 1;
}
static int cj_parse(CJ *j,const char *s,uint32_t n){
 j->text=s;j->bytes=n;j->pos=0;j->count=0;
 if(!s||!n||n>32768||!cj_value(j,0))return 0;cj_space(j);return j->pos==n;
}
static unsigned cj_find(const CJ *j,unsigned obj,const char *key){
 if(obj>=j->count||j->tokens[obj].kind!='{')return CJ_MAX;
 for(unsigned t=obj+1;t<j->tokens[obj].after;t=j->tokens[t+1].after)if(cj_is(j,t,key))return t+1;return CJ_MAX;
}
static int cj_ascii(const CJ *j,unsigned t,char *out,unsigned cap){
 if(t>=j->count||j->tokens[t].kind!='s'||!cap)return 0;unsigned p=j->tokens[t].begin,n=0;
 while(p<j->tokens[t].end){int c=cj_char(j->text,j->tokens[t].end,&p);if(c<32||c>=127||n+1>=cap)return 0;out[n++]=(char)c;}out[n]=0;return 1;
}
static int cj_uint(const CJ *j,unsigned t,unsigned *value){
 if(t>=j->count||j->tokens[t].kind!='d')return 0;unsigned p=j->tokens[t].begin,n=0;
 if(j->tokens[t].end-p>3)return 0;
 while(p<j->tokens[t].end){unsigned c=(uint8_t)j->text[p++];if(c<'0'||c>'9')return 0;n=n*10+c-'0';}
 if(n>256)return 0;*value=n;return 1;
}
static int cj_subset(const CJ *a,unsigned x,const CJ *b,unsigned y,unsigned depth){
 if(depth>12||x>=a->count||y>=b->count||a->tokens[x].kind!=b->tokens[y].kind)return 0;
 char kind=a->tokens[x].kind;
 if(kind=='{'){
  for(unsigned k=x+1;k<a->tokens[x].after;k=a->tokens[k+1].after){char key[96];if(!cj_ascii(a,k,key,sizeof(key)))return 0;unsigned v=cj_find(b,y,key);
   if(cr_same(key,"UUID")){if(!cj_strings(a,k+1,b,v,1))return 0;}
   else if(!cj_subset(a,k+1,b,v,depth+1))return 0;
  }return 1;
 }
 if(kind=='['){unsigned p=x+1,q=y+1;while(p<a->tokens[x].after&&q<b->tokens[y].after){if(!cj_subset(a,p,b,q,depth+1))return 0;p=a->tokens[p].after;q=b->tokens[q].after;}return p==a->tokens[x].after&&q==b->tokens[y].after;}
 if(kind=='s')return cj_strings(a,x,b,y,0);
 unsigned n=a->tokens[x].end-a->tokens[x].begin;
 return n==b->tokens[y].end-b->tokens[y].begin&&cr_eq(a->text+a->tokens[x].begin,b->text+b->tokens[y].begin,n);
}
