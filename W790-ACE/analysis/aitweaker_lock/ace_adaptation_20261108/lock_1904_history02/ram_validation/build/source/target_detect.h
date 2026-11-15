static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID browser_guid={0xb9d4c360,0xbcfb,0x4f9b,{0x92,0x98,0x53,0xc1,0x36,0x98,0x22,0x58}};
static GUID smbios3_guid={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
static GUID smbios_guid={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0,0x90,0x27,0x3f,0xc1,0x4d}};
static GUID tse_guid={0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}};
static GUID setup_guid={0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}};
static int equal_ascii(const uint8_t *s,UN size,const char *want) {
 UN i=0;for(;i<size && want[i];i++)if(s[i]!=(uint8_t)want[i])return 0;
 return i<size && !want[i] && !s[i];
}
static int smbios_string(const uint8_t *s,UN n,uint8_t index,const char *wanted) {
 if(!index)return 0;
 UN p=s[1];for(unsigned i=1;i<index;i++) {while(p<n && s[p])p++;if(p+1>=n || !s[p+1])return 0;p++;}
 return p<n && equal_ascii(s+p,n-p,wanted);
}
static int smbios_table(uint8_t *data,UN size) {
 if(size<6 || size>2*1024*1024 || !memory_present(data,size,0))return 0;
 int board=0,version=0;
 for(UN p=0,count=0;p+6<=size && count<4096;count++) {
  uint8_t type=data[p],length=data[p+1];if(length<4 || length>size-p)return 0;
  UN end=p+length;while(end+1<size && (data[end] || data[end+1]))end++;
  if(end+1>=size)return 0;end+=2;
  if(type==0 && length>=6)version=smbios_string(data+p,end-p,data[p+5],"1904");
  if(type==2 && length>=6)board=smbios_string(data+p,end-p,data[p+5],"Pro WS W790-ACE");
  if(type==127)break;p=end;
 }
 return board && version;
}
static int board_matches(void) {
 for(UN i=0;i<system_table->table_count;i++) {
  CT *ct=&system_table->tables[i];uint8_t *p=ct->table;UN length=0,size=0;uint64_t address=0;
  if(!memcmp(&ct->guid,&smbios3_guid,16)) {
   if(!memory_present(p,24,0) || memcmp(p,"_SM3_",5))continue;
   length=p[6];if(length<24 || length>64 || !memory_present(p,length,0))continue;
   uint32_t n;memcpy(&n,p+12,4);size=n;memcpy(&address,p+16,8);
  } else if(!memcmp(&ct->guid,&smbios_guid,16)) {
   if(!memory_present(p,31,0) || memcmp(p,"_SM_",4))continue;
   length=p[5];if(length<31 || length>64 || !memory_present(p,length,0))continue;
   uint16_t n;uint32_t a;memcpy(&n,p+22,2);memcpy(&a,p+24,4);size=n;address=a;
  } else continue;
  uint8_t sum=0;for(UN j=0;j<length;j++)sum=(uint8_t)(sum+p[j]);
  if(!sum && smbios_table((uint8_t *)(uintptr_t)address,size))return 1;
 }
 return 0;
}
static int image_guid(LOADED *image,GUID *out) {
 uint8_t *path=image->filepath;if(!path)return 0;
 for(UN p=0;p<65536;) {
  if(!memory_present(path+p,4,0))return 0;
  uint16_t n=(uint16_t)(path[p+2]|((uint16_t)path[p+3]<<8));if(n<4 || n>65536-p || !memory_present(path+p,n,0))return 0;
  if(path[p]==4 && path[p+1]==6 && n==20){memcpy(out,path+p+4,16);return 1;}
  if(path[p]==0x7f)return 0;p+=n;
 }
 return 0;
}
