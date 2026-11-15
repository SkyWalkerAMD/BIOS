/* Bounded ASCII JSON for the three-field publication protocol. Non-ASCII and
 * duplicate keys are deliberately refused. No data from this parser is code. */
typedef struct {UN start,end;unsigned after;char type;} JT;
typedef struct {const char *s;UN n,p;unsigned count;JT t[512];} JSON;
static int jhex(char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1;}
static int jchar(const char *s,UN end,UN *p){
 if(*p>=end)return -1;unsigned c=(uint8_t)s[(*p)++];
 if(c!='\\')return c>=32&&c<127?(int)c:-2;
 if(*p>=end)return -2;c=(uint8_t)s[(*p)++];
 if(c=='"'||c=='\\'||c=='/')return (int)c;
 if(c=='b')return 8;if(c=='f')return 12;if(c=='n')return 10;if(c=='r')return 13;if(c=='t')return 9;
 if(c!='u'||end-*p<4)return -2;unsigned v=0;for(unsigned i=0;i<4;i++){int h=jhex(s[(*p)++]);if(h<0)return -2;v=v*16+(unsigned)h;}return v<128?(int)v:-2;
}
static int jeq(JSON *j,unsigned t,const char *s){
 if(t>=j->count||j->t[t].type!='s')return 0;UN p=j->t[t].start,i=0;
 while(p<j->t[t].end){int c=jchar(j->s,j->t[t].end,&p);if(c<0||!s[i]||c!=(uint8_t)s[i++])return 0;}return !s[i];
}
static int jtokens_equal(JSON *j,unsigned a,unsigned b){
 UN p=j->t[a].start,q=j->t[b].start;while(p<j->t[a].end&&q<j->t[b].end)if(jchar(j->s,j->t[a].end,&p)!=jchar(j->s,j->t[b].end,&q))return 0;return p==j->t[a].end&&q==j->t[b].end;
}
static void jspace(JSON *j){while(j->p<j->n&&(j->s[j->p]==' '||j->s[j->p]=='\t'||j->s[j->p]=='\r'||j->s[j->p]=='\n'))j->p++;}
static int jvalue(JSON *j,unsigned depth){
 jspace(j);if(j->p==j->n||j->count==512||depth>12)return 0;
 unsigned id=j->count++;JT *t=&j->t[id];t->start=j->p;t->type=j->s[j->p++];
 if(t->type=='"'){
  t->type='s';t->start=j->p;
  while(j->p<j->n&&j->s[j->p]!='"')if(jchar(j->s,j->n,&j->p)<0)return 0;
  if(j->p==j->n)return 0;t->end=j->p++;
 }else if(t->type=='{'||t->type=='['){
  char close=t->type=='{'?'}':']';jspace(j);
  if(j->p<j->n&&j->s[j->p]==close)j->p++;
  else for(;;){
   if(t->type=='{'){
    unsigned key=j->count;if(j->p==j->n||j->s[j->p]!='"'||!jvalue(j,depth+1))return 0;
    for(unsigned prev=id+1;prev<key;prev=j->t[prev+1].after)if(jtokens_equal(j,key,prev))return 0;
    jspace(j);if(j->p==j->n||j->s[j->p++]!=':')return 0;
   }
   if(!jvalue(j,depth+1))return 0;jspace(j);if(j->p==j->n)return 0;
   if(j->s[j->p]==close){j->p++;break;}if(j->s[j->p++]!=',')return 0;jspace(j);
  }
  t->end=j->p;
 }else{
  j->p=t->start;
  if(t->type=='t'||t->type=='f'||t->type=='n'){
   const char *word=t->type=='t'?"true":t->type=='f'?"false":"null";UN n=t->type=='f'?5:4;
   if(j->n-j->p<n||!eq(j->s+j->p,word,n))return 0;j->p+=n;
  }else{
   t->type='d';if(j->s[j->p]=='-')j->p++;if(j->p==j->n)return 0;
   if(j->s[j->p]=='0')j->p++;else{if(j->s[j->p]<'1'||j->s[j->p]>'9')return 0;while(j->p<j->n&&j->s[j->p]>='0'&&j->s[j->p]<='9')j->p++;}
   if(j->p<j->n&&j->s[j->p]=='.'){UN start=++j->p;while(j->p<j->n&&j->s[j->p]>='0'&&j->s[j->p]<='9')j->p++;if(start==j->p)return 0;}
   if(j->p<j->n&&(j->s[j->p]=='e'||j->s[j->p]=='E')){j->p++;if(j->p<j->n&&(j->s[j->p]=='+'||j->s[j->p]=='-'))j->p++;UN start=j->p;while(j->p<j->n&&j->s[j->p]>='0'&&j->s[j->p]<='9')j->p++;if(start==j->p)return 0;}
  }t->end=j->p;
 }
 t->after=j->count;return 1;
}
static int jparse(JSON *j,const char *s,UN n){memset(j,0,sizeof(*j));j->s=s;j->n=n;if(!s||!n||n>32768||!jvalue(j,0))return 0;jspace(j);return j->p==n;}
static unsigned jfind(JSON *j,unsigned obj,const char *key){if(obj>=j->count||j->t[obj].type!='{')return 512;for(unsigned t=obj+1;t<j->t[obj].after;t=j->t[t+1].after)if(jeq(j,t,key))return t+1;return 512;}
