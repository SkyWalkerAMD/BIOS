/* Strict framing for bounded, non-pipelined HTTP GET responses. Unsupported
 * encodings remain raw diagnostic data; they are never treated as BIOS state. */
static int ascii_equal(const char *s,UN n,const char *name){UN i=0;for(;i<n&&name[i];i++){char a=s[i],b=name[i];if(a>='A'&&a<='Z')a+=32;if(b>='A'&&b<='Z')b+=32;if(a!=b)return 0;}return i==n&&!name[i];}
static ES http_frame(const char *s,UN n,unsigned *code,UN *body_off,UN *body_len,unsigned *encoding){
 *encoding=0;
 *code=0;*body_off=*body_len=0;
 if(n<16||(!eq(s,"HTTP/1.1 ",9)&&!eq(s,"HTTP/1.0 ",9)))return ERR(24);
 for(unsigned i=9;i<12;i++)if(s[i]<'0'||s[i]>'9')return ERR(24);
 if(s[12]!=' ')return ERR(24);*code=(unsigned)(s[9]-'0')*100+(unsigned)(s[10]-'0')*10+s[11]-'0';if(*code<100||*code>599)return ERR(24);
 UN off=12,len=0;int first=1,has_len=0,has_encoding=0;
 while(off<n&&off<8192){
  UN end=off;while(end<n&&s[end]!='\r'){unsigned char c=s[end];if((c<32&&c!='\t')||c==127||end-off>2048)return ERR(24);end++;}
  if(end+1>=n||s[end+1]!='\n')return ERR(24);
  if(first){first=0;off=end+2;continue;}
  if(end==off){off=end+2;if(!has_len){if(*code==204||*code==304)len=0;else return ERR(3);}if(len!=n-off)return ERR(24);*body_off=off;*body_len=len;return 0;}
  if(s[off]==' '||s[off]=='\t')return ERR(24);
  UN colon=off;while(colon<end&&s[colon]!=':')colon++;if(colon==end)return ERR(24);
  UN v=colon+1,z=end;while(v<z&&(s[v]==' '||s[v]=='\t'))v++;while(z>v&&(s[z-1]==' '||s[z-1]=='\t'))z--;
  if(ascii_equal(s+off,colon-off,"content-length")){
   if(has_len||v==z)return ERR(24);has_len=1;
   for(;v<z;v++){if(s[v]<'0'||s[v]>'9'||len>32768/10)return ERR(24);len=len*10+s[v]-'0';if(len>32768)return ERR(4);}
  }else if(ascii_equal(s+off,colon-off,"transfer-encoding"))return ERR(3);
  else if(ascii_equal(s+off,colon-off,"content-encoding")){
   if(has_encoding++)return ERR(24);
   if(ascii_equal(s+v,z-v,"gzip"))*encoding=1;
   else if(!ascii_equal(s+v,z-v,"identity"))return ERR(3);
  }
  off=end+2;
 }
 return ERR(24);
}
