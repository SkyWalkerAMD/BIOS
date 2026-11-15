/* R2: HERO 3107 only. Four B2c hardware-tested initialization packets.
 * No fan mapping, PWM, KCS abort, BMC reset, SPI, SMM, or host EC writes.
 * Before OEM: exact identity, complete stable SDR scan, VERSION_ERR, durable
 * attempt lock, enabled configuration. Every handled exit restores PCI memory bit.
 */
#include "p1.h"
static GUID pci_guid={0x4cf5b200,0x68b8,0x4ca5,{0x9e,0xec,0xb2,0x3e,0x3f,0x50,0x02,0x9a}};
static GUID transport_guid={0x4a1d0e66,0x5271,0x4e22,{0x83,0xfe,0x90,0x92,0x1b,0x74,0x82,0x13}};
static GUID enum_guid={0x30cfe3e7,0x3de1,0x4586,{0xbe,0x20,0xde,0xab,0xa1,0xb3,0xb7,0x93}};
static PCI *card;
static uint8_t pci_config[64],rx[272];
static KCS kcs;
static uint16_t original_command;
static unsigned changed_memory,running,poisoned,delay_left,io_left;
static int io_guard(void){
    uint8_t current[64];
    if(!io_left || poisoned)return 0;
    --io_left;
    report.io_status=card->pci.read(card,0,0,64,current);
    return !FAILED(report.io_status) && probe_pci_gate(current) && eq(current+16,pci_config+16,24);
}
static int rd(void *ctx,int reg,uint8_t *v){
    (void)ctx;if(!io_guard())return 1;
    report.io_status=card->mem.read(card,0,1,reg?0xe8c:0xe88,1,v);
    if(reg && !FAILED(report.io_status))report.last_status=*v;
    return FAILED(report.io_status);
}
static int wr(void *ctx,int reg,uint8_t v){
    (void)ctx;if(!io_guard())return 1;
    report.io_status=card->mem.write(card,0,1,reg?0xe8c:0xe88,1,&v);
    return FAILED(report.io_status);
}
static int delay(unsigned ms){
    if(ms>delay_left || FAILED(gST->bs->stall((UN)ms*1000))){poisoned=1;return 0;}
    delay_left-=ms;return 1;
}
static void delay_ms(void *ctx){(void)ctx;delay(1);}
static int discover(void){
    HANDLE *handles=0;UN count=0;unsigned matches=0;
    ES e=gST->bs->locate_handles(2,&pci_guid,0,&count,&handles);
    if(FAILED(e)||!handles)return 0;
    if(count>4096){gST->bs->free_pool(handles);return 0;}
    for(UN i=0;i<count;i++){
        PCI *p=0;uint8_t c[64];
        if(FAILED(gST->bs->handle_protocol(handles[i],&pci_guid,(void **)&p))||!p)continue;
        if(FAILED(p->pci.read(p,0,0,64,c)))continue;
        if(u32(c)==0x24021a03){matches++;card=p;memcpy(pci_config,c,64);}
    }
    gST->bs->free_pool(handles);
    if(matches!=1||!probe_pci_layout(pci_config))return 0;
    UN seg=0,bus=0,dev=0,fn=0;
    if(FAILED(card->location(card,&seg,&bus,&dev,&fn)) || seg!=0||bus!=4||dev!=1||fn!=0)return 0;
    void *resource=0;uint64_t supported=0;
    e=card->bar_attributes(card,1,&supported,&resource);int ok=0;
    if(!FAILED(e)&&resource){
        const uint8_t *r=resource;
        ok=r[0]==0x8a && u16(r+1)==43 && r[3]==0 && u64(r+14)==(u32(pci_config+20)&0xfffffff0U) && u64(r+38)>=0xe8d;
    }
    if(resource)gST->bs->free_pool(resource);
    logtext("PCI_CONFIG ");logbytes(pci_config,64);
    return ok;
}
static int enable_memory(void){
    uint8_t current[64];ES e=card->pci.read(card,0,0,64,current);
    if(FAILED(e)||!probe_pci_layout(current)||!eq(current+16,pci_config+16,24))return 0;
    original_command=u16(current+4);report.restore_ok=1;
    if(original_command&2)return 1;
    uint16_t requested=(uint16_t)(original_command|2),after=0;
    changed_memory=1;report.restore_ok=0;
    logtext("PCI_ENABLE 16-bit Command only; before=");loghex(original_command,4);logtext("\r\n");
    e=card->pci.write(card,1,4,1,&requested);
    ES re=card->pci.read(card,1,4,1,&after);
    return !FAILED(e)&&!FAILED(re)&&after==requested;
}
static int restore_memory(void){
    if(!changed_memory)return 1;
    uint8_t c[64];ES e=card->pci.read(card,0,0,64,c);
    if(FAILED(e)||!probe_pci_layout(c)||!eq(c+16,pci_config+16,24))return 0;
    uint16_t before=u16(c+4),wanted=(uint16_t)((before&~2U)|(original_command&2)),after=0;
    ES we=0;if(wanted!=before)we=card->pci.write(card,1,4,1,&wanted);
    e=card->pci.read(card,1,4,1,&after);
    logtext("PCI_RESTORE write=");loghex(we,16);logtext(" read=");loghex(e,16);logtext(" after=");loghex(after,4);logtext("\r\n");
    if(FAILED(e)||after!=wanted)return 0;
    changed_memory=0;report.restore_ok=1;return 1;
}
static int ready(void){
    unsigned zero=0;
    for(unsigned i=0;i<31;i++){
        uint8_t s;if(rd(0,1,&s))return 0;
        logtext("READY_STATUS ");loghex(s,2);logtext("\r\n");
        if(s==0){if(++zero==3)return 1;}
        else if(s==255)zero=0;
        else {result((s&0xc0)==0xc0?"KCS error state: use B2c recovery separately; no automatic abort.":"KCS is not idle; no takeover or automatic retry.");return 0;}
        if(i<30&&!delay(1000))return 0;
    }
    result("KCS did not become idle within 31 samples.");return 0;
}
/* 1=success, 0=completion-code rejection (optional item), -1=transport failure.
 * A rejected optional command never fabricates a value. Transport errors poison
 * this driver instance and cannot be automatically retried. */
static int query(uint8_t f,uint8_t c,const uint8_t *p,size_t len,size_t *n){
 *n=0;
 if(poisoned || audit_len+1200>=sizeof(audit)){poisoned=1;return -1;}
 logtext("TX ");loghex(f,2);logtext("/");loghex(c,2);logtext(" ");logbytes(p,len);
 int e=kcs_query(&kcs,f,c,p,len,rx,sizeof(rx),n);report.requests++;
 report.kcs_error=(uint32_t)e;report.last_status=kcs.last_status;
 logtext("RX ");logtext(kcs_error(e));logtext(" ");logbytes(rx,*n);
 if(e){poisoned=1;return -1;}return rx[2]?0:1;
}
static int read_common(void){
 size_t n;int q;
 if(query(6,1,0,0,&n)!=1 || !probe_bmc_identity(rx,n)){
  result("Device ID differs from the validated ASUS 1.3.13 identity.");return 0;
 }
 report.identity=1;
 value_dec(V_DEVICE,rx[3]);value_hex(V_REVISION,rx[4],2);
 value_text(V_FIRMWARE,"1.03.13");value_text(V_IPMI,"2.0");
 value_hex(V_MFG,(uint32_t)rx[9]|((uint32_t)rx[10]<<8)|((uint32_t)rx[11]<<16),6);
 value_hex(V_PRODUCT,u16(rx+12),4);
 q=query(6,4,0,0,&n);if(q<0)return 0;
 if(q==1&&n==5){
  value_text(V_SELFTEST,rx[3]==0x55?"PASSED":rx[3]==0x56?"Not implemented":rx[3]==0x57?"Hardware error - see log":"Failure / device-specific result");
 }
 q=query(6,0x25,0,0,&n);if(q<0)return 0;
 if(q==1&&n==11){
  value_text(V_WDT_RUNNING,(rx[3]&0x40)?"Running":"Stopped");
  const char *uses[]={"Reserved","BIOS FRB2","BIOS POST","OS load","OS management software","OEM"};
  unsigned use=rx[3]&7;value_text(V_WDT_USE,use<6?uses[use]:"Reserved");
  const char *actions[]={"No action","Hard reset","Power down","Power cycle"};
  unsigned a=rx[4]&7;value_text(V_WDT_POLICY,a<4?actions[a]:"Reserved");
  value_dec(V_WDT_INITIAL,u16(rx+7));value_dec(V_WDT_REMAINING,u16(rx+9));
 }
 q=query(6,0x2f,0,0,&n);if(q<0)return 0;
 if(q==1&&n==4)value_text(V_SEL_LOGGING,(rx[3]&8)?"Enabled":"Disabled");
 return 1;
}
static int read_lan(void){
 size_t n;uint8_t channel=0;
 /* Discover the medium rather than assuming the donor's channel number. */
 for(uint8_t i=1;i<=11;i++){
  int q=query(6,0x42,&i,1,&n);if(q<0)return 0;
  if(q==1&&n==12&&(rx[3]&15)==i&&(rx[4]&0x7f)==4){channel=i;break;}
 }
 if(!channel){value_text(V_CHANNEL,"No LAN channel identified");return 1;}
 value_dec(V_CHANNEL,channel);
 const uint8_t selectors[]={4,3,6,12,5};
 const unsigned ids[]={V_SOURCE,V_IP,V_MASK,V_GATEWAY,V_MAC};
 for(unsigned i=0;i<5;i++){
  uint8_t request[]={channel,selectors[i],0,0};int q=query(0xc,2,request,4,&n);if(q<0)return 0;
  if(q!=1)continue;
  if(i==0&&n==5){const char *sources[]={"Unspecified","Static","BMC DHCP","BIOS DHCP","Other dynamic"};value_text(V_SOURCE,(rx[4]&15)<5?sources[rx[4]&15]:"Reserved");}
  else if(i>0&&i<4&&n==8)value_ip(ids[i],rx+4);
  else if(i==4&&n==10){char s[18];for(unsigned j=0;j<6;j++){s[3*j]="0123456789ABCDEF"[rx[4+j]>>4];s[3*j+1]="0123456789ABCDEF"[rx[4+j]&15];s[3*j+2]=j==5?0:':';}value_text(V_MAC,s);}
 }
 return 1;
}
static int read_sel(void){
 size_t n;uint8_t info[17];int q=query(0xa,0x40,0,0,&n);if(q<0)return 0;
 if(q!=1||n!=17)return 1;memcpy(info,rx,17);
 unsigned count=u16(rx+4);value_dec(V_SEL_COUNT,count);value_dec(V_SEL_FREE,u16(rx+6));
 value_text(V_SEL_OVERFLOW,(rx[16]&128)?"Yes":"No");
 if(!count){value_text(V_SEL_RANGE,"Empty event log");return 1;}
 uint16_t next=0,visited[16];unsigned shown=0;
 for(;shown<16 && next!=0xffff;shown++){
  for(unsigned j=0;j<shown;j++)if(visited[j]==next){value_text(V_SEL_RANGE,"Record chain changed; refresh required");return 1;}
  visited[shown]=next;
  uint8_t request[]={0,0,(uint8_t)next,(uint8_t)(next>>8),0,255};
  q=query(0xa,0x43,request,6,&n);if(q<0)return 0;
  if(q!=1||n!=21 || (next && u16(rx+5)!=next)){value_text(V_SEL_RANGE,"Record unavailable / log changed");return 1;}
  next=u16(rx+3);
  /* Preserve every byte. OEM entries must not be decoded as standard events. */
  char text[96];unsigned pos=0;const char *tag=rx[7]==2?"System: ":"OEM: ";
  while(*tag)text[pos++]=*tag++;
  for(unsigned j=5;j<21;j++){text[pos++]="0123456789ABCDEF"[rx[j]>>4];text[pos++]="0123456789ABCDEF"[rx[j]&15];if(j<20)text[pos++]=' ';}
  text[pos]=0;value_text(V_SEL0+shown,text);
 }
 q=query(0xa,0x40,0,0,&n);if(q<0)return 0;
 if(q!=1||n!=17||!eq(info,rx,17))value_text(V_SEL_RANGE,"Log changed during read; refresh required");
 else value_text(V_SEL_RANGE,next==0xffff?"Complete log (up to 16 records)":"First 16 records; remaining records not read");
 return 1;
}
ES p1_collect(void){
 if(running)return ERR(20);if(poisoned)return ERR(15);running=1;
 ES status=ERR(7);void *existing=0;delay_left=45000;io_left=200000;
 for(unsigned i=0;i<V_COUNT;i++)value_text(i,i>=V_SEL0?"-":"Unavailable");
 report.identity=0;logtext("P1_READ_BEGIN\r\n");detect_board();
 if(!same(report.board,"ROG MAXIMUS Z790 HERO")||!same(report.bios,"3107")){
  result("P1 hardware access requires ROG MAXIMUS Z790 HERO BIOS 3107.");goto out;
 }
 if(FAILED(gST->bs->locate_protocol(&enum_guid,0,&existing))){result("PCI enumeration not ready.");goto out;}
 existing=0;if(gST->bs->locate_protocol(&transport_guid,0,&existing)!=ERR(14)){
  result("An IPMI transport already owns the card; raw KCS is not used.");goto out;
 }
 if(!discover()||!enable_memory()){result("ASPEED PCI location/BAR or memory-enable verification failed.");goto out;}
 kcs=(KCS){.read=rd,.write=wr,.delay_ms=delay_ms};
 if(!ready()||!read_common()||!read_lan()||!read_sel())goto out;
 result("BMC status, watchdog, LAN and SEL queried; read-only session.");status=0;
out:
 if(!restore_memory()){poisoned=1;result("PCI restore unconfirmed; stop testing.");status=ERR(7);}
 if(FAILED(status)&&report.identity&&poisoned)result("KCS read failed; this driver instance will not retry.");
 value_text(V_RESULT,report.result);last_refresh=status;running=0;
 logtext("P1_READ_END status=");loghex(status,16);logtext("\r\n");return status;
}
