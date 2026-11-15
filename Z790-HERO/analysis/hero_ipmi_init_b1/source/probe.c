/* HERO IPMI B1: standalone candidate initialization experiment.
 * E/P first collects the read baseline using the real-tested A2 transport.
 * Only a separate I key, exact BMC fingerprint, complete SDR baseline,
 * VERSION_ERR assertion, BIOS 3107 and a working log authorize four fixed
 * OEM packets. They are a candidate derived from R1, not a donor DXE loader.
 * BMC changes have no verified rollback and may persist. PCI restoration
 * restores only the temporary Command bit, not any BMC state.
 */
#include "efi_min.h"
#include "probe_core.h"

static GUID pci_guid={0x4cf5b200,0x68b8,0x4ca5,{0x9e,0xec,0xb2,0x3e,0x3f,0x50,0x02,0x9a}};
static GUID loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID global_guid={0x8be4df61,0x93ca,0x11d2,{0xaa,0x0d,0x00,0xe0,0x98,0x03,0x2b,0x8c}};
static GUID smbios2_guid={0xeb9d2d31,0x2d88,0x11d3,{0x9a,0x16,0x00,0x90,0x27,0x3f,0xc1,0x4d}};
static GUID smbios3_guid={0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
static ST *st;
static FILEP *logfile;
static char logbuf[512*1024];
static size_t loglen,logsaved;
static int logtruncated;
static char logname[24],board[96],bios[96];
static PCI *card;
static uint8_t config[64],response[272],sensor_seen[256],sensor_ids[256];
static uint8_t sensor_event[256],sensor_type[256],baseline_seen[256];
static size_t sensor_count;
static ES last_io;
static int transport_failed;
static int memory_write_attempted;
static uint16_t saved_command;
static int bmc_matches,resident_transport,sdr_complete,snapshot_read_failed;
static int version_error_reported,version_error_asserted,init_attempted;

void *memset(void *p,int c,size_t n) { uint8_t *b=p; while (n--) *b++=(uint8_t)c; return p; }
void *memcpy(void *p,const void *q,size_t n) { uint8_t *a=p; const uint8_t *b=q; while (n--) *a++=*b++; return p; }
static uint16_t le16(const uint8_t *p) { return p[0]|((uint16_t)p[1]<<8); }
static uint32_t le32(const uint8_t *p) { return le16(p)|((uint32_t)le16(p+2)<<16); }
static uint64_t le64(const uint8_t *p) { return le32(p)|((uint64_t)le32(p+4)<<32); }
static int equal(const void *a,const void *b,size_t n) {
    const uint8_t *x=a,*y=b; while (n--) if (*x++!=*y++) return 0; return 1;
}
static void console(const char *s) {
    C16 w[192]; size_t n=0;
    if (!st->out || !st->out->out) return;
    while (*s) {
        w[n++]=(unsigned char)*s++;
        if (n==191 || !*s) { w[n]=0; st->out->out(st->out,w); n=0; }
    }
}
static void emit(const char *s,int screen) {
    if (screen) console(s);
    while (*s) {
        if (loglen<sizeof(logbuf)-1) logbuf[loglen++]=*s;
        else logtruncated=1;
        s++;
    }
    logbuf[loglen]=0;
}
static void say(const char *s) { emit(s,1); }
static void hex(uint64_t v,unsigned digits,int screen) {
    const char *h="0123456789ABCDEF"; char b[18];
    if (digits>16) digits=16;
    for (unsigned i=0;i<digits;i++) b[i]=h[(v>>((digits-1-i)*4))&15];
    b[digits]=0; emit(b,screen);
}
static void number(uint64_t v,int screen) {
    char b[24]; size_t i=sizeof(b)-1; b[i]=0;
    do { b[--i]=(char)('0'+v%10); v/=10; } while (v);
    emit(b+i,screen);
}
static void raw(const uint8_t *p,size_t n) {
    for (size_t i=0;i<n;i++) { if (i) emit(" ",0); hex(p[i],2,0); }
    emit("\r\n",0);
}
static void checkpoint(void) {
    if (!logfile || logsaved==loglen) return;
    UN n=loglen-logsaved;
    ES e=logfile->write(logfile,&n,logbuf+logsaved);
    if (FAILED(e) || n!=loglen-logsaved) {
        console("LOG WRITE FAILED. Photograph the console; do not treat the log as complete.\r\n");
        logfile->close(logfile); logfile=0; return;
    }
    logsaved=loglen;
    e=logfile->flush(logfile);
    if (FAILED(e)) {
        console("LOG FLUSH FAILED. Log durability is unconfirmed.\r\n");
        logfile->close(logfile); logfile=0;
    }
}
static void open_log(HANDLE image) {
    LOADED *li=0; FS *fs=0; FILEP *root=0,*tag=0,*existing=0;
    if (FAILED(st->bs->handle_protocol(image,&loaded_guid,(void **)&li)) || !li) return;
    if (FAILED(st->bs->handle_protocol(li->device,&fs_guid,(void **)&fs)) || !fs) return;
    if (FAILED(fs->open_volume(fs,&root)) || !root) return;
    ES e=root->open(root,&tag,(C16 *)L"\\HERO-PROBE-USB.TAG",1,0);
    if (FAILED(e) || !tag) { root->close(root); return; }
    char marker[32]={0}; UN bytes=sizeof(marker);
    e=tag->read(tag,&bytes,marker); tag->close(tag);
    if (FAILED(e) || bytes!=20 || !equal(marker,"HERO-IPMI-INIT--B1\r\n",20)) {
        root->close(root); return;
    }
    for (unsigned i=0;i<1000;i++) {
        C16 name[]=L"\\HEROIPMI-000.TXT";
        name[10]=(C16)('0'+i/100); name[11]=(C16)('0'+(i/10)%10); name[12]=(C16)('0'+i%10);
        e=root->open(root,&existing,name,1,0);
        if (!FAILED(e)) { if (existing) existing->close(existing); continue; }
        if (e!=ERR(14)) break; /* Never overwrite an unreadable existing file. */
        e=root->open(root,&logfile,name,0x8000000000000003ULL,0);
        if (!FAILED(e) && logfile) {
            for (unsigned j=1;name[j];j++) logname[j-1]=(char)name[j];
        } else logfile=0;
        break;
    }
    root->close(root);
}
static char key(void) {
    if (!st->in || !st->in->read) return 'q';
    KEY k; ES e;
    for (;;) {
        e=st->in->read(st->in,&k);
        if (!FAILED(e)) {
            if (k.scan==0x17) return 'q';
            if (k.unicode>='A' && k.unicode<='Z') return (char)(k.unicode-'A'+'a');
            if (k.unicode<128) return (char)k.unicode;
        } else if (e!=ERR(6)) return 'q';
        if (!st->in->wait) return 'q';
        UN index=0;
        if (FAILED(st->bs->wait_for_event(1,&st->in->wait,&index))) return 'q';
    }
}
static void clocklog(const char *label) {
    ETIME t; ES e=st->rt->get_time(&t,0); emit(label,0);
    if (FAILED(e)) { emit("time unavailable\r\n",0); return; }
    number(t.year,0); emit("-",0); number(t.month,0); emit("-",0); number(t.day,0);
    emit(" ",0); number(t.hour,0); emit(":",0); number(t.minute,0); emit(":",0); number(t.second,0);
    emit(" (firmware local clock)\r\n",0);
}
static void sm_string(const uint8_t *start,const uint8_t *end,uint8_t idx,char *out,size_t cap) {
    out[0]=0; if (!idx) return;
    for (unsigned s=1;start<end && *start;s++) {
        const uint8_t *p=start; while (p<end && *p) p++;
        if (p==end) return;
        if (s==idx) {
            size_t n=(size_t)(p-start); if (n>=cap) n=cap-1;
            for (size_t j=0;j<n;j++) out[j]=(start[j]>=32 && start[j]<=126)?(char)start[j]:'?';
            out[n]=0; return;
        }
        start=p+1;
    }
}
static int checksum(const uint8_t *p,size_t n) { uint8_t s=0; while (n--) s+=*p++; return s==0; }
static void get_board(void) {
    const uint8_t *table=0; size_t length=0;
    if (st->table_count>1024) return;
    for (unsigned pass=0;pass<2 && !table;pass++) {
        for (UN i=0;i<st->table_count;i++) {
            CT *t=&st->tables[i]; const uint8_t *p=t->table;
            if (!p) continue;
            if (pass==0 && equal(&t->guid,&smbios3_guid,16) && equal(p,"_SM3_",5) &&
                    p[6]>=24 && p[6]<=64 && checksum(p,p[6])) {
                table=(const uint8_t *)(UN)le64(p+16); length=le32(p+12); break;
            }
            if (pass==1 && equal(&t->guid,&smbios2_guid,16) && equal(p,"_SM_",4) &&
                    p[5]>=31 && p[5]<=64 && checksum(p,p[5])) {
                table=(const uint8_t *)(UN)le32(p+24); length=le16(p+22); break;
            }
        }
    }
    if (!table || length<6 || length>16*1024*1024 || (UN)table+length<(UN)table) return;
    const uint8_t *p=table,*end=table+length;
    while ((size_t)(end-p)>=6) {
        uint8_t type=p[0],size=p[1];
        if (size<4 || size>(size_t)(end-p)-2) break;
        const uint8_t *q=p+size;
        while (q+1<end && !(q[0]==0 && q[1]==0)) q++;
        if (q+1>=end) break;
        if (type==0 && size>5 && !bios[0]) sm_string(p+size,q+1,p[5],bios,sizeof(bios));
        if (type==2 && size>5 && !board[0]) sm_string(p+size,q+1,p[5],board,sizeof(board));
        p=q+2; if (type==127) break;
    }
}
static void protocols(void) {
    struct { const char *name; GUID guid; } list[]={
        {"PI PCI enumeration complete (30CFE3E7)",{0x30cfe3e7,0x3de1,0x4586,{0xbe,0x20,0xde,0xab,0xa1,0xb3,0xb7,0x93}}},
        {"Donor notification 72338391 (identity unverified)",{0x72338391,0xfb43,0x44a1,{0xa9,0xa2,0x64,0xfe,0xe1,0xfc,0x5e,0x41}}},
        {"Variable architecture",{0x1e5668e2,0x8481,0x11d4,{0xbc,0xf1,0x00,0x80,0xc7,0x3c,0x88,0x81}}},
        {"Variable write architecture",{0x6441f818,0x6362,0x4e44,{0xb5,0x70,0x7d,0xba,0x31,0xdd,0x24,0x53}}},
        {"ASUS HWM",{0x78039142,0x4378,0x48ef,{0xbb,0x5d,0xf6,0x3b,0xf2,0xc5,0xde,0xb5}}},
        {"ASUS BMC ready",{0xd9b90d4f,0x7f30,0x4b02,{0x97,0x75,0x1d,0xc6,0x84,0x84,0x3c,0x99}}},
        {"ASUS BMC parameters",{0xbb31e7e8,0x94e0,0x43ca,{0xaa,0xd0,0x69,0x4c,0xfa,0xb3,0xff,0x5c}}},
        {"AMI IPMI transport",{0x4a1d0e66,0x5271,0x4e22,{0x83,0xfe,0x90,0x92,0x1b,0x74,0x82,0x13}}}
    };
    for (size_t i=0;i<sizeof(list)/sizeof(list[0]);i++) {
        void *p=0; ES e=st->bs->locate_protocol(&list[i].guid,0,&p);
        if (i==7 && !FAILED(e)) resident_transport=1;
        emit("Protocol ",0); emit(list[i].name,0); emit(FAILED(e)?" ABSENT status=":" PRESENT status=",0);
        hex(e,16,0); emit("\r\n",0);
    }
}
static int find_card(void) {
    HANDLE *handles=0; UN count=0; unsigned matches=0;
    ES e=st->bs->locate_handles(2,&pci_guid,0,&count,&handles);
    say("PCI enumeration status=0x"); hex(e,16,1); say("\r\n");
    if (FAILED(e) || !handles) return 0;
    if (count>4096) { st->bs->free_pool(handles); return 0; }
    for (UN i=0;i<count;i++) {
        PCI *p=0; uint8_t c[64];
        if (FAILED(st->bs->handle_protocol(handles[i],&pci_guid,(void **)&p)) || !p) continue;
        if (FAILED(p->pci.read(p,0,0,sizeof(c),c))) continue;
        if (le32(c)!=0x24021a03) continue;
        matches++; card=p; memcpy(config,c,64);
        UN seg=0,bus=0,dev=0,fn=0; e=p->location(p,&seg,&bus,&dev,&fn);
        say("ASPEED 1A03:2402 at ");
        if (FAILED(e)) say("[location unavailable]");
        else { hex(seg,4,1); say(":"); hex(bus,2,1); say(":"); hex(dev,2,1); say("."); hex(fn,1,1); }
        say(" revision=0x"); hex(c[8],2,1); say(" command=0x"); hex(le16(c+4),4,1); say("\r\n");
        emit("PCI_CONFIG_00_3F ",0); raw(c,64);
        say("BAR1=0x"); hex(le32(c+20),8,1); say("\r\n");
    }
    st->bs->free_pool(handles);
    say("Matching PCI functions: "); number(matches,1); say("\r\n");
    if (matches!=1 || !probe_pci_layout(config)) {
        say("KCS gate CLOSED: need one ready card and an assigned 32-bit BAR1.\r\n");
        return 0;
    }
    void *resources=0; uint64_t supports=0;
    e=card->bar_attributes(card,1,&supports,&resources);
    say("BAR1 resource status=0x"); hex(e,16,1); say("\r\n");
    int valid=0;
    if (!FAILED(e) && resources) {
        const uint8_t *r=resources;
        /* EFI_PCI_IO_PROTOCOL specifies QWORD ACPI address descriptors (0x8A).
         * One BAR has one range; do not walk an unbounded descriptor list. */
        if (r[0]==0x8a && le16(r+1)==43 && r[3]==0) {
            uint64_t base=le64(r+14),len=le64(r+38);
            say("BAR1 base=0x"); hex(base,16,1); say(" length=0x"); hex(len,16,1); say("\r\n");
            valid=base==(le32(config+20)&0xfffffff0U) && len>=0xe8d;
        }
        st->bs->free_pool(resources);
    }
    if (!valid) say("KCS gate CLOSED: BAR1 range could not be validated.\r\n");
    return valid;
}
static ES read_command(uint16_t *command) {
    /* EfiPciIoWidthUint16=1; one word at 4 never accesses Status at 6. */
    return card->pci.read(card,1,4,1,command);
}
static int prepare_kcs(int allow_enable) {
    uint8_t current[64];
    ES e=card->pci.read(card,0,0,sizeof(current),current);
    if (FAILED(e) || !probe_pci_layout(current) || !equal(current+16,config+16,24)) {
        say("KCS gate CLOSED: card/BAR state changed since discovery.\r\n");
        return 0;
    }
    uint16_t command=le16(current+4);
    if (command&2) {
        say("PCI memory decoding already enabled; no PCI write required.\r\n");
        return 1;
    }
    if (!allow_enable) {
        say("QUERY_SKIPPED: memory decoding is disabled; E is required to enable it.\r\n");
        return 0;
    }
    say("PCI_MEMORY_ENABLE_REQUESTED: temporary Command bit 1 only.\r\n");
    checkpoint();
    if (!logfile) {
        say("QUERY_SKIPPED: a writable log is required for temporary PCI changes.\r\n");
        return 0;
    }
    saved_command=command;
    uint16_t requested=(uint16_t)(command|2),after=0;
    say("PCI_COMMAND_BEFORE=0x"); hex(command,4,1);
    say(" REQUESTED=0x"); hex(requested,4,1); say("\r\n");
    checkpoint();
    if (!logfile) return 0;
    /* Mark before the call: even an error may have partially affected hardware. */
    memory_write_attempted=1;
    e=card->pci.write(card,1,4,1,&requested);
    ES re=read_command(&after);
    say("PCI_ENABLE_WRITE_STATUS=0x"); hex(e,16,1);
    say(" READ_STATUS=0x"); hex(re,16,1);
    say(" AFTER=0x"); hex(after,4,1); say("\r\n"); checkpoint();
    if (FAILED(e) || FAILED(re) || after!=requested) {
        say("PCI_MEMORY_ENABLE_FAILED: no KCS command will be sent.\r\n");
        return 0;
    }
    say("PCI_MEMORY_ENABLED_VERIFIED\r\n");
    return 1;
}
static int restore_memory(void) {
    if (!memory_write_attempted) return 1;
    uint8_t current[64];
    ES e=card->pci.read(card,0,0,sizeof(current),current);
    say("PCI_RESTORE_CONFIG_READ_STATUS=0x"); hex(e,16,1); say("\r\n");
    if (FAILED(e) || le32(current)!=0x24021a03 || (current[14]&0x7f)!=0) {
        say("PCI_MEMORY_RESTORE_UNCONFIRMED: cannot verify the same PCI function.\r\n");
        return 0;
    }
    uint16_t before=le16(current+4);
    /* Restore only our memory bit; preserve any other bits changed externally. */
    uint16_t requested=(uint16_t)((before&~2U)|(saved_command&2)),after=0;
    say("PCI_RESTORE_BEFORE=0x"); hex(before,4,1);
    say(" REQUESTED=0x"); hex(requested,4,1); say("\r\n"); checkpoint();
    ES we=0;
    if (requested!=before) we=card->pci.write(card,1,4,1,&requested);
    ES re=read_command(&after);
    say("PCI_RESTORE_WRITE_STATUS=0x"); hex(we,16,1);
    say(" READ_STATUS=0x"); hex(re,16,1);
    say(" AFTER=0x"); hex(after,4,1); say("\r\n");
    if (FAILED(re) || (after&2)!=(saved_command&2)) {
        say("PCI_MEMORY_RESTORE_UNCONFIRMED\r\n");
        return 0;
    }
    if (FAILED(we)) say("PCI restore write reported an error; readback confirms the memory bit.\r\n");
    if ((after&~2U)!=(saved_command&~2U))
        say("PCI_OTHER_COMMAND_BITS_CHANGED: preserved; full original Command is not confirmed.\r\n");
    say("PCI_MEMORY_RESTORED_VERIFIED\r\n");
    memory_write_attempted=0;
    return 1;
}
static int io_read(void *ctx,int reg,uint8_t *v) {
    PCI *p=ctx;
    last_io=p->mem.read(p,0,1,reg?0xe8c:0xe88,1,v);
    return FAILED(last_io);
}
static int io_write(void *ctx,int reg,uint8_t v) {
    PCI *p=ctx;
    last_io=p->mem.write(p,0,1,reg?0xe8c:0xe88,1,&v);
    return FAILED(last_io);
}
static void delay_ms(void *ctx) { (void)ctx; st->bs->stall(1000); }
static KCS kcs;
static int query(uint8_t netfn,uint8_t cmd,const uint8_t *p,size_t n,size_t *used) {
    if (transport_failed) return 0;
    emit("TX netfn=",0); hex(netfn,2,0); emit(" cmd=",0); hex(cmd,2,0); emit(" data=",0); raw(p,n);
    checkpoint();
    int e=kcs_query(&kcs,netfn,cmd,p,n,response,sizeof(response),used);
    emit("RX transport=",0); emit(kcs_error(e),0); emit(" status=",0); hex(kcs.last_status,2,0);
    emit(" pci_io=",0); hex(last_io,16,0); emit(" bytes=",0); raw(response,*used);
    if (e) {
        say("BMC query stopped: "); say(kcs_error(e)); say(". No further commands or automatic retry.\r\n");
        transport_failed=1; checkpoint(); return 0;
    }
    if (response[2]) {
        say("BMC completion code=0x"); hex(response[2],2,1); say(" for "); hex(netfn,2,1);
        say("/"); hex(cmd,2,1); say("\r\n"); checkpoint(); return 0;
    }
    checkpoint(); return 1;
}
static void read_sensor(uint8_t id) {
    size_t n=0;
    if (id==0xfb) version_error_reported=version_error_asserted=0;
    if (!query(4,0x2d,&id,1,&n)) { snapshot_read_failed=1; return; }
    say("Sensor 0x"); hex(id,2,1);
    if (n<5) { say(" response too short\r\n"); snapshot_read_failed=1; return; }
    say(" raw=0x"); hex(response[3],2,1); say(" flags=0x"); hex(response[4],2,1);
    if (response[4]&0x20) say(" READING_UNAVAILABLE");
    if (!(response[4]&0x40)) say(" SCANNING_DISABLED");
    if (sensor_event[id]!=1 && n>=6) {
        uint16_t states=response[5]|(n>=7 ? (uint16_t)(response[6]&0x7f)<<8 : 0);
        say(" DISCRETE_STATE=0x"); hex(states,4,1);
        if (id==0xfb && sensor_type[id]==0x2b && sensor_event[id]==0x6f && n>=7) {
            version_error_reported=!(response[4]&0x20) && (response[4]&0x40);
            version_error_asserted=version_error_reported && (states&0x10);
            say(version_error_asserted?" VERSION_ERR_ASSERTED":" VERSION_ERR_NOT_ASSERTED_OR_UNAVAILABLE");
        }
    } else if (sensor_event[id]==1 && !(response[4]&0x20) && (response[4]&0x40)) say(" READING_REPORTED");
    say("\r\n");
}
static void sdr_scan(void) {
    sensor_count=0; sdr_complete=0; snapshot_read_failed=0;
    version_error_reported=version_error_asserted=0;
    memset(sensor_seen,0,sizeof(sensor_seen));
    memset(sensor_event,0,sizeof(sensor_event));
    memset(sensor_type,0,sizeof(sensor_type));
    size_t n=0;
    if (!query(0x0a,0x20,0,0,&n)) return;
    if (n<6) { say("SDR repository response too short.\r\n"); return; }
    unsigned declared=le16(response+4);
    say("SDR repository record count: "); number(declared,1); say("\r\n");
    if (!declared) { say("EMPTY_REPOSITORY: no SDRs to read.\r\n"); return; }
    uint16_t next=0,visited[128]; size_t records=0;
    while (next!=0xffff && records<128) {
        for (size_t j=0;j<records;j++) if (visited[j]==next) {
            say("SDR list cycle detected. Stopped.\r\n"); return;
        }
        visited[records]=next;
        uint8_t request[6]={0,0,(uint8_t)next,(uint8_t)(next>>8),0,255};
        if (!query(0x0a,0x23,request,sizeof(request),&n)) {
            say("SDR scan incomplete. Whole-record read failed; no reservation or partial-read fallback was attempted.\r\n"); return;
        }
        if (n<10 || n!=10U+response[9]) { say("Invalid SDR record length. Stopped.\r\n"); return; }
        uint16_t record_id=le16(response+5);
        if (next!=0 && record_id!=next) { say("SDR record ID mismatch. Stopped.\r\n"); return; }
        next=le16(response+3); records++;
        SENSOR s;
        if (probe_sensor(response+5,n-5,&s)) {
            say("SDR 0x"); hex(record_id,4,1); say(" sensor=0x"); hex(s.number,2,1);
            say(" name="); say(s.name); say("\r\n");
            if (s.owner==0x20 && s.lun==0 && s.share_count<=1) {
                if (!sensor_seen[s.number]) {
                    sensor_seen[s.number]=1; sensor_ids[sensor_count++]=s.number;
                    sensor_event[s.number]=s.event_type; sensor_type[s.number]=s.type;
                    read_sensor(s.number);
                    if (transport_failed) return;
                }
            } else say("Skipping bridged, nonzero-LUN or shared sensor; raw SDR retained.\r\n");
        }
    }
    if (next==0xffff) {
        say("SDR_SCAN_COMPLETE\r\n");
        if (records==declared) sdr_complete=1;
        else say("SDR_COUNT_CHANGED_OR_MISMATCH: this snapshot cannot authorize initialization.\r\n");
    }
    else say("SDR_SCAN_LIMIT_128: additional records not read.\r\n");
    say("Readable direct sensor IDs discovered: "); number(sensor_count,1); say("\r\n");
}
static void target_summary(const char *label) {
    const CANDIDATE_STEP *s=candidate_step(1); unsigned present=0;
    say(label); say(" target IDs present in SDR: ");
    for (unsigned i=0;i<s->length;i+=2) {
        uint8_t id=s->data[i];
        if (sensor_seen[id]) { hex(id,2,1); say(" "); present++; }
    }
    number(present,1); say("/16\r\n");
    if (init_attempted) {
        say("NEW_SDR_SENSOR_IDS: ");
        for (unsigned i=0;i<256;i++) if (sensor_seen[i] && !baseline_seen[i]) { hex(i,2,1); say(" "); }
        say("\r\n");
    }
    say("VERSION_ERR current status: ");
    say(!version_error_reported?"UNAVAILABLE":version_error_asserted?"ASSERTED":"NOT_ASSERTED");
    say("\r\n"); checkpoint();
}
static int init_gate(void) {
    return !init_attempted && !transport_failed && !resident_transport && bmc_matches &&
        equal(bios,"3107",5) && sdr_complete && !snapshot_read_failed &&
        version_error_reported && version_error_asserted && logfile && !logtruncated;
}
static void initialize_candidate(void) {
    if (!init_gate()) { say("OEM_GATE_CLOSED: baseline/fingerprint/log requirements not met.\r\n"); return; }
    /* Recheck after the user has had time to read the warning. */
    size_t n=0;
    if (!prepare_kcs(0) || !query(6,1,0,0,&n) || !probe_bmc_identity(response,n)) {
        say("OEM_GATE_CLOSED: fresh card/device identity check failed.\r\n"); return;
    }
    read_sensor(0xfb);
    if (!init_gate()) { say("OEM_GATE_CLOSED: VERSION_ERR or log changed.\r\n"); return; }
    say("OEM_AUTHORIZED_BY_I: candidate changes BMC state; persistence/rollback unverified.\r\n");
    checkpoint();
    if (!logfile || logtruncated) return;
    init_attempted=1; candidate_arm(&kcs);
    unsigned accepted=0;
    for (unsigned i=0;i<4;i++) {
        const CANDIDATE_STEP *s=candidate_step(i);
        say("OEM_STEP "); number(i+1,1); say("/4\r\n");
        emit("TX netfn=30 cmd=",0); hex(s->command,2,0); emit(" data=",0); raw(s->data,s->length);
        checkpoint();
        if (!logfile || logtruncated) {
            say("OEM_STOPPED_LOG_FAILURE: no more OEM packets will be sent.\r\n"); break;
        }
        n=0;
        int e=candidate_query(&kcs,i,response,sizeof(response),&n);
        emit("RX transport=",0); emit(kcs_error(e),0); emit(" status=",0); hex(kcs.last_status,2,0);
        emit(" pci_io=",0); hex(last_io,16,0); emit(" bytes=",0); raw(response,n);
        if (e) {
            say("OEM_TRANSPORT_FAILED: "); say(kcs_error(e)); say(". No retry.\r\n");
            transport_failed=1; checkpoint(); break;
        }
        say("OEM_COMPLETION=0x"); hex(response[2],2,1); say("\r\n");
        if (response[2]) { say("OEM_REJECTED: remaining OEM packets skipped.\r\n"); checkpoint(); break; }
        accepted++; checkpoint();
    }
    candidate_disarm(&kcs);
    say(accepted==4?"OEM_SEQUENCE_ACCEPTED":"OEM_SEQUENCE_INCOMPLETE");
    say(" acknowledged="); number(accepted,1); say("/4\r\n");
    say("BMC changes are NOT rolled back. Accepted commands do not prove working sensors.\r\n");
    checkpoint();
    if (!transport_failed && logfile && !logtruncated) {
        say("POST_INIT_SNAPSHOT_BEGIN\r\n"); clocklog("After initialization: ");
        sdr_scan(); target_summary("AFTER"); say("POST_INIT_SNAPSHOT_END\r\n");
    }
}
ES EA efi_main(HANDLE image,ST *system) {
    st=system;
    if (!st || !st->bs || !st->rt || st->hdr.sig!=0x5453595320494249ULL) return ERR(2);
    st->bs->set_watchdog(0,0,0,0); /* Application session only; no BMC watchdog command. */
    open_log(image);
    say("\r\nHERO IPMI INIT B1 - experimental candidate, no BIOS image flashing\r\n");
    say("E/P reads the baseline. A separate I key can send four BMC OEM commands.\r\n");
    say("OEM effects may persist; no verified BMC rollback. This is not a DXE loader.\r\n");
    if (logfile) { say("Log on marked boot volume: "); say(logname); say("\r\n"); }
    else say("LOG UNAVAILABLE. Copy the USB marker file too, or photograph the results.\r\n");
    clocklog("Started: ");
    get_board(); say("Board: "); say(board[0]?board:"[unavailable]"); say("\r\nBIOS: "); say(bios[0]?bios:"[unavailable]"); say("\r\n");
    uint8_t sb=255; UN sb_len=1; ES e=st->rt->get_variable((C16 *)L"SecureBoot",&global_guid,0,&sb_len,&sb);
    emit("SecureBoot status=",0); hex(e,16,0); emit(" value=",0); hex(sb,2,0); emit("\r\n",0);
    protocols();
    int card_ok=find_card(),board_ok=probe_board_gate(board,bios);
    if (!board_ok) say("KCS gate CLOSED: supported target is ROG MAXIMUS Z790 HERO / BIOS 3001 or 3107.\r\n");
    checkpoint();
    if (card_ok && board_ok) {
        if (le16(config+4)&2) {
            say("\r\nP = query BMC identity + SDRs + readings; Q = exit.\r\n");
        } else {
            say("\r\nPCI memory decoding is disabled.\r\n");
            say("E = temporarily enable PCI memory decoding and query BMC; Q = exit.\r\n");
            say("E changes a volatile PCI bit. Cleanup will restore and verify it.\r\n");
            say("If the system hangs or loses power, cleanup cannot be guaranteed.\r\n");
        }
        say("Baseline uses standard reads. OEM initialization requires a separate I key later.\r\n");
        char c;
        do { c=key(); } while (c!='q' && c!=((le16(config+4)&2)?'p':'e'));
        if (c!='q' && prepare_kcs(c=='e')) {
            kcs=(KCS){.ctx=card,.read=io_read,.write=io_write,.delay_ms=delay_ms};
            say("\r\nQUERY_BEGIN\r\n");
            size_t n=0;
            if (query(6,1,0,0,&n)) {
                bmc_matches=probe_bmc_identity(response,n);
                say("GET_DEVICE_ID_OK\r\n");
                say(bmc_matches?"BMC_FINGERPRINT_MATCH_A2\r\n":"BMC_FINGERPRINT_MISMATCH: OEM mode disabled.\r\n");
                if (n>=14) {
                    say("BMC firmware bytes: "); hex(response[5],2,1); say(" "); hex(response[6],2,1);
                    say(" (Web version may use a different format)\r\n");
                    say("Manufacturer ID=0x"); hex(le32(response+9)&0xffffff,6,1);
                    say(" Product ID=0x"); hex(le16(response+12),4,1); say("\r\n");
                    sdr_scan();
                    memcpy(baseline_seen,sensor_seen,sizeof(baseline_seen));
                    target_summary("BEFORE");
                } else say("Get Device ID payload too short; SDR scan skipped.\r\n");
            }
            checkpoint();
            while (!transport_failed && !logtruncated && (sensor_count || init_attempted)) {
                say("\r\nR = rescan SDRs and readings; Q = finish. Raw bytes are not degrees/RPM.\r\n");
                if (init_gate()) {
                    say("I = send the candidate OEM sequence ONCE (changes BMC state).\r\n");
                    say("Effects may persist; no verified rollback. PCI cleanup cannot undo BMC changes.\r\n");
                    say("Packets: 30/90 80; 30/94 fixed 16-ID list; 30/92 0000; 30/02 01.\r\n");
                } else if (!init_attempted) say("OEM_GATE_CLOSED: requires BIOS 3107, A2 BMC identity, complete baseline, VERSION_ERR, log, no resident IPMI.\r\n");
                if (init_attempted) say("Wait about 30 seconds, then R for another snapshot. I cannot run again in this session.\r\n");
                checkpoint();
                do { c=key(); } while (c!='r' && c!='q' && c!='i');
                if (c=='q') break;
                if (c=='i') initialize_candidate();
                else { clocklog("Rescan: "); sdr_scan(); target_summary(init_attempted?"AFTER_RESCAN":"BASELINE_RESCAN"); }
                checkpoint();
            }
            say("QUERY_END\r\n");
        } else say("QUERY_SKIPPED\r\n");
    }
    int restored=restore_memory();
    if (!restored) say("PCI cleanup is unconfirmed. Shut down/restart before normal use; retain this log.\r\n");
    say("\r\nPCI cleanup does not roll back BMC OEM effects. No CAP/driver boot validation was performed.\r\n");
    if (logtruncated) console("LOG_BUFFER_LIMIT: log is truncated.\r\n");
    say("PROBE_END\r\n"); checkpoint();
    if (logfile) { logfile->close(logfile); logfile=0; console("Log closed. "); console(logname); console("\r\n"); }
    console("Press Q to return to the boot menu.\r\n");
    while (key()!='q') {}
    return 0;
}
