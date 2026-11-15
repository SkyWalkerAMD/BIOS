/* M1: HERO 3107 only. Four B2c hardware-tested initialization packets.
 * No fan mapping, PWM, KCS abort, BMC reset, SPI, SMM, or host EC writes.
 * Before OEM: exact identity, complete stable SDR scan, VERSION_ERR, durable
 * attempt lock, saved opt-in. Every handled exit restores PCI memory bit.
 */
#include "m1.h"
static GUID pci_guid={0x4cf5b200,0x68b8,0x4ca5,{0x9e,0xec,0xb2,0x3e,0x3f,0x50,0x02,0x9a}};
static GUID transport_guid={0x4a1d0e66,0x5271,0x4e22,{0x83,0xfe,0x90,0x92,0x1b,0x74,0x82,0x13}};
static GUID enum_guid={0x30cfe3e7,0x3de1,0x4586,{0xbe,0x20,0xde,0xab,0xa1,0xb3,0xb7,0x93}};
static PCI *card;
static uint8_t pci_config[64],rx[272],seen[256];
static KCS kcs;
static uint16_t original_command;
static unsigned changed_memory,running,poisoned,delay_left,io_left;
static int fb_sdr;
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
static int query(uint8_t netfn,uint8_t cmd,const uint8_t *data,size_t len,size_t *n){
    *n=0;if(poisoned || audit_len+1200>=sizeof(audit)){result("Stopped: transport or audit buffer unavailable.");return 0;}
    logtext("TX ");loghex(netfn,2);logtext("/");loghex(cmd,2);logtext(" ");logbytes(data,len);
    report.requests++;
    int e=kcs_query(&kcs,netfn,cmd,data,len,rx,sizeof(rx),n);
    report.kcs_error=(uint32_t)e;report.last_status=kcs.last_status;
    logtext("RX ");logtext(kcs_error(e));logtext(" ");logbytes(rx,*n);
    if(e){poisoned=1;result("KCS transfer failed; no retry in this driver session.");return 0;}
    if(rx[2]){result("BMC rejected a standard read; initialization stopped.");return 0;}
    return 1;
}
static int read_sensor(uint8_t id,uint8_t type,uint8_t event){
    size_t n;if(!query(4,0x2d,&id,1,&n)||n<5)return 0;
    if(id==0xfb){
        report.version_valid=n>=7 && type==0x2b && event==0x6f && (rx[4]&0x60)==0x40;
        report.version_asserted=report.version_valid && (rx[5]&0x10)!=0;
    }
    const CANDIDATE_STEP *s=candidate_step(1);
    for(unsigned i=0;i<s->length;i+=2)if(id==s->data[i] && event==1 && (rx[4]&0x60)==0x40)report.readable++;
    return 1;
}
static int snapshot(void){
    size_t n;uint8_t repo[272];size_t repo_n;
    report.targets=report.readable=report.records=report.version_valid=report.version_asserted=0;
    memset(seen,0,sizeof(seen));fb_sdr=0;
    if(!query(10,0x20,0,0,&n)||n<17)return 0;
    repo_n=n;memcpy(repo,rx,n);unsigned declared=u16(rx+4);
    if(!declared || declared>128)return 0;
    uint16_t next=0,visited[128];unsigned count=0;
    while(next!=0xffff && count<128){
        for(unsigned j=0;j<count;j++)if(visited[j]==next)return 0;
        visited[count]=next;
        uint8_t request[6]={0,0,(uint8_t)next,(uint8_t)(next>>8),0,255};
        if(!query(10,0x23,request,6,&n)||n<10||n!=10U+rx[9]||rx[7]!=0x51)return 0;
        uint16_t rid=u16(rx+5);if(next && rid!=next)return 0;
        next=u16(rx+3);count++;report.records=count;
        SENSOR sensor;
        if(probe_sensor(rx+5,n-5,&sensor)){
            if(sensor.owner!=0x20 || sensor.lun!=0 || sensor.share_count>1)continue;
            if(seen[sensor.number])return 0;
            seen[sensor.number]=1;
            if(sensor.number==0xfb)fb_sdr=sensor.type==0x2b && sensor.event_type==0x6f && same(sensor.name,"VERSION_ERR");
            const CANDIDATE_STEP *s=candidate_step(1);
            for(unsigned j=0;j<s->length;j+=2)if(sensor.number==s->data[j]){
                uint8_t expected=j>=16?4:(sensor.number==1||sensor.number==3||sensor.number==0x1c||sensor.number==0x1d)?1:2;
                if(sensor.type!=expected || sensor.event_type!=1)return 0;
                report.targets++;
            }
            if(!read_sensor(sensor.number,sensor.type,sensor.event_type))return 0;
        }else if(rx[8]==1 || rx[8]==2)return 0;
    }
    if(next!=0xffff || count!=declared || !fb_sdr || !report.version_valid)return 0;
    /* Reject a changing repository, including timestamps, before any OEM write. */
    if(!query(10,0x20,0,0,&n)||n!=repo_n||!eq(repo,rx,n))return 0;
    return 1;
}
ES EA engine_run(uint32_t initialize){
    if(running)return ERR(20);
    if(poisoned){result("Transport previously failed; restart the driver session after diagnosis.");return ERR(7);}
    CONFIG cfg;
    if(initialize && (FAILED(config_read(&cfg))||!cfg.enabled)){result("Initialization disabled. Enable and save Auto initialize first.");return ERR(15);}
    if(initialize && report.attempted){result("OEM attempt already consumed this driver session; no repeat.");return ERR(20);}
    if(initialize && FAILED(lock_read())){result("A previous OEM attempt is locked. Review its log before clearing the lock.");return ERR(15);}
    running=1;changed_memory=0;delay_left=45000;io_left=200000;report.restore_ok=1;
    ES status=ERR(7);int success=0;
    logtext(initialize?"\r\nM1_INITIALIZE_BEGIN\r\n":"\r\nM1_READ_ONLY_BEGIN\r\n");
    detect_board();logtext("BOARD ");logtext(report.board);logtext(" BIOS ");logtext(report.bios);logtext("\r\n");
    if(!same(report.board,"ROG MAXIMUS Z790 HERO")||!same(report.bios,"3107")){result("Unsupported target. Required: ROG MAXIMUS Z790 HERO BIOS 3107.");status=ERR(3);goto out;}
    void *p=0;
    if(FAILED(gST->bs->locate_protocol(&enum_guid,0,&p))){result("PCI enumeration is not complete.");goto out;}
    p=0;
    if(gST->bs->locate_protocol(&transport_guid,0,&p)!=ERR(14)){result("Resident IPMI transport or protocol lookup error: exclusive access unavailable.");goto out;}
    if(audit_len+50000>=sizeof(audit)){result("Audit buffer capacity insufficient for another full operation.");goto out;}
    if(!discover()){result("Expected one ASPEED 1A03:2402 rev 01 at 0000:04:01.0 with valid BAR1.");goto out;}
    if(!enable_memory()){result("PCI memory decoding enable/readback failed.");goto out;}
    kcs=(KCS){.read=rd,.write=wr,.delay_ms=delay_ms};
    if(!ready())goto out;
    size_t n;
    report.identity=0;
    if(!query(6,1,0,0,&n)||!probe_bmc_identity(rx,n)){result("BMC Device ID does not match the tested 1.3.13 fingerprint, or query failed.");goto out;}
    report.identity=1;
    if(!snapshot()){result("Full, stable SDR baseline or VERSION_ERR validation failed.");goto out;}
    if(!initialize){result("Status refreshed; no OEM command sent.");status=0;goto out;}
    if(!report.version_asserted){
        if(report.targets==16){result("Already initialized: 16 target SDRs present and VERSION_ERR clear. No OEM replay.");status=0;}
        else result("VERSION_ERR is clear but target SDRs are incomplete; no OEM replay.");
        goto out;
    }
    if(!query(6,1,0,0,&n)||!probe_bmc_identity(rx,n)||!read_sensor(0xfb,0x2b,0x6f)||!report.version_valid||!report.version_asserted){result("Fresh identity/VERSION_ERR check failed; no OEM sent.");goto out;}
    if(FAILED(config_read(&cfg))||!cfg.enabled||FAILED(lock_read())){result("Configuration or attempt lock changed; no OEM sent.");goto out;}
    /* Durable latch PRECEDES the first hardware side effect, survives reset.
     * A successful SetVariable is read back. Failure can never authorize OEM. */
    if(FAILED(lock_write(1))){result("Cannot persist/verify the attempt lock; no OEM sent.");goto out;}
    report.attempted=1;report.acknowledged=0;candidate_arm(&kcs);
    for(unsigned i=0;i<4;i++){
        const CANDIDATE_STEP *s=candidate_step(i);
        if(audit_len+1200>=sizeof(audit)){result("OEM stopped: audit buffer full; attempt remains locked.");goto out;}
        logtext("OEM_TX 30/");loghex(s->command,2);logtext(" ");logbytes(s->data,s->length);
        report.requests++;
        int e=candidate_query(&kcs,i,rx,sizeof(rx),&n);
        report.kcs_error=(uint32_t)e;report.last_status=kcs.last_status;
        logtext("OEM_RX ");logtext(kcs_error(e));logtext(" ");logbytes(rx,n);
        if(e || n!=3 || rx[2]){if(e)poisoned=1;result("OEM sequence failed or reply was unexpected; no retry; attempt remains locked.");goto out;}
        report.acknowledged++;
    }
    if(!snapshot() || report.version_asserted || report.targets!=16){result("Four OEM commands accepted; post-check incomplete. Attempt remains locked.");goto out;}
    success=1;status=0;
out:
    candidate_disarm(&kcs);
    if(!restore_memory()){report.restore_ok=0;poisoned=1;result("PCI restoration unconfirmed. Stop testing and inspect the log.");status=ERR(7);success=0;}
    if(success){
        if(FAILED(lock_write(0))){result("Initialized and PCI restored; attempt lock could not be cleared.");status=ERR(7);}
        else result("Initialized: 4/4 accepted, 16 target SDRs, VERSION_ERR clear. Fan RPM not validated.");
    }
    lock_read();running=0;logtext("M1_RUN_END status=");loghex(status,16);logtext("\r\n");return status;
}
