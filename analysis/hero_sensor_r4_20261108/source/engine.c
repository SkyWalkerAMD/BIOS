/* R4: HERO 3107 only. R3 initialization plus the live-tested CHA1 read map.
 * No PWM/type/mode, hide, KCS abort, BMC reset, SPI, SMM, or host EC writes.
 * Before OEM: exact identity, complete stable SDR scan, VERSION_ERR, durable
 * attempt lock, enabled configuration. Every handled exit restores PCI memory bit.
 */
#include "r2.h"
static GUID pci_guid={0x4cf5b200,0x68b8,0x4ca5,{0x9e,0xec,0xb2,0x3e,0x3f,0x50,0x02,0x9a}};
static GUID transport_guid={0x4a1d0e66,0x5271,0x4e22,{0x83,0xfe,0x90,0x92,0x1b,0x74,0x82,0x13}};
static GUID enum_guid={0x30cfe3e7,0x3de1,0x4586,{0xbe,0x20,0xde,0xab,0xa1,0xb3,0xb7,0x93}};
static PCI *card;
static uint8_t pci_config[64],rx[272],seen[256];
static KCS kcs;
static uint16_t original_command;
static unsigned changed_memory,running,poisoned,delay_left,io_left;
static int fb_sdr,fan_schema;
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
typedef struct {uint8_t mode,rpm[15],pwm[15],type[15];} FAN_TABLES;
static int fan_tables(FAN_TABLES *f){
 uint8_t *dst[4]={&f->mode,f->rpm,f->pwm,f->type};
 for(unsigned i=0;i<4;i++){
  uint8_t p[2]={(uint8_t)i,0};size_t n=0;size_t wanted=i?15:1;
  if(!query(0x30,0x9a,p,2,&n)||n!=wanted+3){result("Fan GET length/status failed; no further initialization.");return 0;}
  memcpy(dst[i],rx+3,wanted);
 }
 logtext("FAN_TABLES mode=");loghex(f->mode,2);logtext(" RPM ");logbytes(f->rpm,15);
 logtext("FAN_PWM ");logbytes(f->pwm,15);logtext("FAN_TYPE ");logbytes(f->type,15);return 1;
}
static int fan_controls_tested(const FAN_TABLES *f){
 if(f->mode)return 0;
 for(unsigned i=0;i<15;i++)if(f->pwm[i]!=0||f->type[i]!=1)return 0;
 return 1;
}
static int fan_prepare(const FAN_TABLES *before,FAN_TABLES *wanted){
 FAN_TABLES current;
 if(!fan_tables(&current)||!eq(&current,before,sizeof(current))){result("Fan tables changed after board ID; attempt locked, no sensor enable.");return 0;}
 *wanted=*before;
 if(before->rpm[2]==0){
  wanted->rpm[2]=0x62;
  /* Final complete before-image comparison immediately before authorization. */
  if(!fan_tables(&current)||!eq(&current,before,sizeof(current))){result("Fan tables changed before RPM SET; attempt locked.");return 0;}
  if(audit_len+1800>=sizeof(audit)||!rpm_arm(&kcs,before->rpm,wanted->rpm))return 0;
  logtext("FAN_SET 30/9A 01 01 ");logbytes(wanted->rpm,15);report.requests++;
  size_t n=0;int e=rpm_query(&kcs,rx,sizeof(rx),&n);
  report.kcs_error=(uint32_t)e;report.last_status=kcs.last_status;
  logtext("FAN_SET_RX ");logtext(kcs_error(e));logtext(" ");logbytes(rx,n);
  if(e){poisoned=1;result("RPM SET reply failed/unknown; no retry or rollback. Attempt locked.");return 0;}
 }else logtext("FAN_MAP_ALREADY_62_NO_SET\r\n");
 if(!fan_tables(&current)||!eq(&current,wanted,sizeof(current))){result("RPM/controls readback differs; no sensor enable; attempt locked.");return 0;}
 logtext("FAN_MAP_VERIFIED_BEFORE_SENSOR_ENABLE\r\n");return 1;
}
static int fan_observe(void){
 uint8_t id=0x20;unsigned usable=0,positive=0;size_t n=0;
 if(!seen[id]){logtext("FAN_SENSOR20_ABSENT\r\n");return 1;}
 for(unsigned i=0;i<3;i++){
  if(i&&!delay(1000))return 0;
  if(!query(4,0x2d,&id,1,&n)||n<5)return 0;
  int valid=(rx[4]&0x60)==0x40;usable+=(unsigned)valid;
  if(valid&&rx[3])positive++;
  logtext("FAN_SAMPLE id20 raw=");loghex(rx[3],2);logtext(" flags=");loghex(rx[4],2);
  logtext(" usable=");loghex((unsigned)valid,2);
  if(valid&&fan_schema){logtext(" rpm_hex=");loghex((unsigned)rx[3]*120U,4);}
  logtext("\r\n");
 }
 logtext("FAN_OBSERVATION usable=");loghex(usable,2);logtext(" positive=");loghex(positive,2);
 logtext(" samples=03 (RPM presence is not an initialization retry trigger)\r\n");return 1;
}
static int fan_sdr_exact(const uint8_t *p,size_t n){
 static const uint8_t expected[59]={0x22,0x00,0x51,0x01,0x36,0x20,0x00,0x20,0x1d,0x01,0x77,0x68,0x04,0x01,0x05,0x70,0x05,0x70,0x07,0x07,0x00,0x12,0x00,0x00,0x78,0x00,0x00,0x00,0x00,0x00,0x00,0x38,0xe0,0x0d,0xff,0x00,0xfa,0xed,0xe1,0x00,0x03,0x03,0x01,0x01,0x00,0x00,0x00,0xcb,0x4d,0x42,0x5f,0x43,0x48,0x41,0x5f,0x46,0x41,0x4e,0x31};
 /* Record ID may differ; every remaining SDR byte, including units/M=120,
  * name, thresholds and event masks, must match before interpreting RPM. */
 return n==sizeof(expected)&&eq(p+2,expected+2,sizeof(expected)-2);
}
static int read_sensor(uint8_t id,uint8_t type,uint8_t event){
    size_t n;if(!query(4,0x2d,&id,1,&n)||n<5)return 0;
    if(id==0xfb){
        report.version_valid=n>=7 && type==0x2b && event==0x6f && (rx[4]&0x60)==0x40;
        report.version_asserted=report.version_valid && (rx[5]&0x10)!=0;
    }
    const CANDIDATE_STEP *s=candidate_step(1);
    for(unsigned i=0;i<s->length;i+=2)if(id==s->data[i] && event==1 && (rx[4]&0x60)==0x40)report.readable++;
    if(id==0xfb || seen[id]==2){
        logtext("SENSOR id=");loghex(id,2);logtext(" type=");loghex(type,2);
        logtext(" event=");loghex(event,2);logtext(" raw=");loghex(rx[3],2);
        logtext(" flags=");loghex(rx[4],2);logtext("\r\n");
    }
    return 1;
}
static int snapshot(void){
    logtext("SDR_SNAPSHOT_BEGIN\r\n");
    size_t n;uint8_t repo[272];size_t repo_n;
    report.targets=report.readable=report.records=report.version_valid=report.version_asserted=0;
    memset(seen,0,sizeof(seen));fb_sdr=0;fan_schema=0;
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
            if(sensor.number==0x20){fan_schema=fan_sdr_exact(rx+5,n-5);if(!fan_schema)return 0;}
            if(sensor.number==0xfb)fb_sdr=sensor.type==0x2b && sensor.event_type==0x6f && same(sensor.name,"VERSION_ERR");
            const CANDIDATE_STEP *s=candidate_step(1);
            for(unsigned j=0;j<s->length;j+=2)if(sensor.number==s->data[j]){
                uint8_t expected=j>=16?4:(sensor.number==1||sensor.number==3||sensor.number==0x1c||sensor.number==0x1d)?1:2;
                if(sensor.type!=expected || sensor.event_type!=1)return 0;
                report.targets++;seen[sensor.number]=2;
            }
            if(!read_sensor(sensor.number,sensor.type,sensor.event_type))return 0;
        }else if(rx[8]==1 || rx[8]==2)return 0;
    }
    if(next!=0xffff || count!=declared || !fb_sdr || !report.version_valid)return 0;
    /* Reject a changing repository, including timestamps, before any OEM write. */
    if(!query(10,0x20,0,0,&n)||n!=repo_n||!eq(repo,rx,n))return 0;
    logtext("SDR_SNAPSHOT_END targets=");loghex(report.targets,2);logtext(" readable=");loghex(report.readable,2);logtext(" version_asserted=");loghex(report.version_asserted,2);logtext("\r\n");
    return 1;
}
ES EA engine_run(uint32_t initialize){
    if(running)return ERR(20);
    if(poisoned){result("Transport previously failed; restart the driver session after diagnosis.");return ERR(7);}
    CONFIG cfg;
    if(initialize && (FAILED(config_read(&cfg))||!cfg.enabled)){result("Initialization disabled. Save enabled configuration first.");return ERR(15);}
    if(initialize && report.attempted){result("OEM attempt already consumed this driver session; no repeat.");return ERR(20);}
    if(initialize && FAILED(lock_read())){result("A previous OEM attempt is locked. Review its log before clearing the lock.");return ERR(15);}
    running=1;changed_memory=0;delay_left=45000;io_left=200000;report.restore_ok=1;
    ES status=ERR(7);int success=0;FAN_TABLES fan_before={0},fan_wanted={0};
    logtext(initialize?"\r\nR4_SENSORS_INITIALIZE_BEGIN\r\n":"\r\nR4_SENSORS_READ_ONLY_BEGIN\r\n");
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
    report.identity=1;logtext("BMC_ID ");logbytes(rx,n);
    if(!snapshot()){result("Full, stable SDR baseline or VERSION_ERR validation failed.");goto out;}
    if(!fan_tables(&fan_before))goto out;
    if(!initialize){if(!fan_observe())goto out;result("Status refreshed; fan GETs only, no OEM SET sent.");status=0;goto out;}
    if(!report.version_asserted){
        if(report.targets==16){if(!fan_observe())goto out;result("Already initialized: 16 target SDRs and VERSION_ERR clear. Fan map observed, no OEM replay.");status=0;}
        else result("VERSION_ERR is clear but target SDRs are incomplete; no OEM replay.");
        goto out;
    }
    if(seen[0x20]){result("VERSION_ERR asserted but CHA1 already visible; no automatic scanner reset or OEM replay.");goto out;}
    if(!fan_controls_tested(&fan_before)){result("Custom fan mode/PWM/type present; preserved. No OEM initialization.");goto out;}
    if(fan_before.rpm[2]!=0&&fan_before.rpm[2]!=0x62){result("Custom CHA1 RPM mapping conflict; preserved. No OEM initialization.");goto out;}
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
        if(i==0&&!fan_prepare(&fan_before,&fan_wanted))goto out;
    }
    if(!snapshot() || report.version_asserted || report.targets!=16){result("Four OEM commands accepted; post-check incomplete. Attempt remains locked.");goto out;}
    {FAN_TABLES after;
     if(!fan_tables(&after)||!eq(&after,&fan_wanted,sizeof(after))){result("Post-init fan maps changed; attempt stays locked.");goto out;}
     if(!fan_observe()){result("Post-init fan reads failed; attempt stays locked.");goto out;}
    }
    success=1;status=0;
out:
    candidate_disarm(&kcs);
    if(!restore_memory()){report.restore_ok=0;poisoned=1;result("PCI restoration unconfirmed. Stop testing and inspect the log.");status=ERR(7);success=0;}
    if(success){
        if(FAILED(lock_write(0))){result("Initialized and PCI restored; attempt lock could not be cleared.");status=ERR(7);}
        else result("Initialized: 4/4 accepted, CHA1 map62 verified, 16 target SDRs, VERSION_ERR clear. See FAN_OBSERVATION for actual RPM.");
    }
    lock_read();running=0;logtext("R4_SENSORS_END status=");loghex(status,16);logtext("\r\n");return status;
}
static void dmi_result(const char *s){strcopy(r3_report.dashboard_result,sizeof(r3_report.dashboard_result),s);logtext("DASHBOARD_RESULT: ");logtext(s);logtext("\r\n");}
static int dmi_get(uint8_t selector,uint8_t *data,size_t *length){
 size_t n=0;*length=0;if(poisoned||audit_len+1800>=sizeof(audit))return 0;
 logtext("DMI_GET selector=");loghex(selector,2);logtext(" offset=0 count=192\r\n");report.requests++;
 int e=dashboard_read(&kcs,selector,rx,sizeof(rx),&n);report.kcs_error=(uint32_t)e;report.last_status=kcs.last_status;
 logtext("DMI_RX ");logtext(kcs_error(e));logtext(" ");logbytes(rx,n);
 if(e){poisoned=1;return 0;}
 if(n<4||rx[2]||rx[3]>=192||n!=(size_t)rx[3]+4)return 0;
 *length=rx[3];memcpy(data,rx+4,*length);return 1;
}
static int old_identity_shape(const uint8_t *p,size_t n,unsigned strings){
 if(!n)return 1;if(p[n-1])return 0;unsigned found=0;size_t start=0;
 for(size_t i=0;i<n;i++)if(!p[i]){if(i==start)return 0;found++;start=i+1;}else if(p[i]<32||p[i]>126)return 0;
 return found==strings;
}
ES EA engine_dashboard(uint32_t write){
 if(write>1)return ERR(2);if(running)return ERR(20);
 if(poisoned){dmi_result("Transport/PCI state is uncertain; Dashboard stage blocked.");return ERR(7);}
 CONFIG cfg;if(write&&(config_read(&cfg)||!cfg.enabled)){dmi_result("Dashboard writes disabled by configuration.");return ERR(15);}
 if(write&&r3_report.dmi_attempted){dmi_result("Dashboard write authorization already consumed this session.");return ERR(20);}
 running=1;changed_memory=0;delay_left=12000;io_left=80000;ES status=ERR(7);int latch=0,success=0;
 char sensor_result[160];strcopy(sensor_result,sizeof(sensor_result),report.result);
 LOCAL_IDENTITY source;uint8_t before[2][192];size_t old_n[2]={0,0};unsigned changes=0;
 r3_report.dmi_matched=0;
 logtext(write?"\r\nR4_DASHBOARD_SYNC_BEGIN\r\n":"\r\nR4_DASHBOARD_COMPARE_BEGIN\r\n");
 logtext("DMI_GET_SIDE_EFFECT: missing backend files may be created empty.\r\n");
 detect_board();
 if(r3_report.source_status||!local_identity.dashboard_valid||!same(report.board,"ROG MAXIMUS Z790 HERO")||!same(report.bios,"3107")){
  dmi_result("Local SMBIOS identity is incomplete or unsupported; sensor stage is independent.");status=ERR(3);goto out;
 }
 source=local_identity;logtext("DMI_SOURCE table_crc=");loghex(source.table_crc,8);logtext(" bytes=");loghex(source.table_bytes,8);logtext("\r\n");
 void *p=0;if(gST->bs->locate_protocol(&enum_guid,0,&p)){dmi_result("PCI enumeration incomplete.");goto out;}
 p=0;if(gST->bs->locate_protocol(&transport_guid,0,&p)!=ERR(14)){dmi_result("Exclusive KCS access unavailable.");goto out;}
 if(audit_len+14000>=sizeof(audit)){dmi_result("Insufficient audit capacity before hardware access.");goto out;}
 if(!discover()||!enable_memory()||!ready()){dmi_result("PCI/KCS readiness failed.");goto out;}
 kcs=(KCS){.read=rd,.write=wr,.delay_ms=delay_ms};
 size_t n;if(!query(6,1,0,0,&n)||!probe_bmc_identity(rx,n)){dmi_result("Exact BMC fingerprint check failed.");goto out;}
 /* Pre-read both resources before any setter; board then BIOS matches live test. */
 for(unsigned i=0;i<2;i++){
  const uint8_t *request=i?source.bios_request:source.board_request;size_t wanted=(i?source.bios_bytes:source.board_bytes)-1;
  if(!dmi_get(request[0],before[i],&old_n[i])){dmi_result("Dashboard pre-read failed or exceeded complete-file bound.");goto out;}
  if(old_n[i]==wanted&&eq(before[i],request+1,wanted))r3_report.dmi_matched|=1U<<request[0];
  else{
   changes|=1U<<i;
   if(old_n[i]>wanted||!old_identity_shape(before[i],old_n[i],i?2:4)){
    dmi_result("Existing identity has unsupported length/shape; setter does not truncate. No write.");goto out;
   }
  }
 }
 dmi_lock_read();
 if(!changes){dmi_result("Both Dashboard files already match local SMBIOS; no SET or NVRAM write.");status=0;goto out;}
 if(!write){dmi_result("Dashboard differs from local SMBIOS; comparison only, no SET issued.");status=0;goto out;}
 if(r3_report.dmi_locked){dmi_result("Prior Dashboard attempt remains locked; no write or retry.");status=ERR(15);goto out;}
 if(identity_read()||!local_identity.dashboard_valid||!eq(&source,&local_identity,sizeof(source))){dmi_result("SMBIOS changed after pre-read; no write.");goto out;}
 if(!query(6,1,0,0,&n)||!probe_bmc_identity(rx,n)){dmi_result("Fresh BMC identity check failed.");goto out;}
 if(config_read(&cfg)||!cfg.enabled||dmi_lock_read()){dmi_result("Configuration/attempt state changed before SET.");goto out;}
 if(dmi_lock_write(1)){dmi_result("Cannot persist/verify Dashboard attempt latch; no SET.");goto out;}
 latch=1;r3_report.dmi_attempted=1;
 for(unsigned i=0;i<2;i++)if(changes&(1U<<i)){
  const uint8_t *request=i?source.bios_request:source.board_request;size_t bytes=i?source.bios_bytes:source.board_bytes;
  if(audit_len+3600>=sizeof(audit)||!dashboard_arm(&kcs,request,bytes)){dmi_result("Dashboard authorization/log bound failed; latch retained.");goto out;}
  logtext("DMI_SET 30/04 ");logbytes(request,bytes);report.requests++;
  int e=dashboard_write(&kcs,rx,sizeof(rx),&n);report.kcs_error=(uint32_t)e;report.last_status=kcs.last_status;
  logtext("DMI_SET_RX ");logtext(kcs_error(e));logtext(" ");logbytes(rx,n);
  if(e||n!=4||rx[2]||rx[3]!=bytes-1){if(e)poisoned=1;dmi_result("SET rejected/unknown or unexpected acknowledgment; no retry; latch retained.");goto out;}
  r3_report.dmi_written|=1U<<request[0];
  if(!dmi_get(request[0],before[i],&old_n[i])||old_n[i]!=bytes-1||!eq(before[i],request+1,bytes-1)){
   dmi_result("SET acknowledged but exact readback failed; no retry; latch retained.");goto out;
  }r3_report.dmi_matched|=1U<<request[0];
 }
 success=1;status=0;dmi_result("Dashboard selector2/0 synchronized and exact byte readback verified.");
out:
 dashboard_disarm(&kcs);
 if(!restore_memory()){poisoned=1;report.restore_ok=0;status=ERR(7);success=0;dmi_result("PCI restoration unconfirmed; Dashboard latch retained.");}
 if(latch&&success&&dmi_lock_write(0)){status=ERR(7);dmi_result("Identity matched and PCI restored; Dashboard latch clear failed.");}
 dmi_lock_read();strcopy(report.result,sizeof(report.result),sensor_result);running=0;
 logtext("R4_DASHBOARD_END status=");loghex(status,16);logtext("\r\n");return status;
}
