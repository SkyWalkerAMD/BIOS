/* B1: bounded KCS transport. Standard reads retain their separate whitelist.
 * A separately armed API permits only the four immutable candidate packets,
 * in order, once; any transfer/completion error disarms the sequence.
 * These OEM packets change BMC state; their persistence is not established. */
#include "probe_core.h"

static int allowed(uint8_t netfn,uint8_t cmd,const uint8_t *p,size_t n) {
    if (netfn==6 && cmd==1) return n==0;
    if (netfn==0x0a && cmd==0x20) return n==0;
    if (netfn==0x0a && cmd==0x23)
        return n==6 && p && p[0]==0 && p[1]==0 && p[4]==0 && p[5]==255;
    if (netfn==4 && cmd==0x2d) return n==1 && p;
    return 0;
}
static int status(KCS *k,uint8_t *s) {
    if (!k->budget) return K_TIMEOUT;
    --k->budget;
    if (k->read(k->ctx,1,s)) return K_IO;
    k->last_status=*s;
    if (*s==255) return K_ALL_FF;
    return K_OK;
}
static int wait_mask(KCS *k,uint8_t mask,uint8_t value,uint8_t *s) {
    int e;
    for (;;) {
        if ((e=status(k,s))) return e;
        if ((*s & mask)==value) return K_OK;
        if ((*s & 0xc0)==0xc0) return K_STATE;
        k->delay_ms(k->ctx);
    }
}
static int drain_dummy(KCS *k,uint8_t s) {
    uint8_t ignored;
    return (s&1) && k->read(k->ctx,0,&ignored) ? K_IO : K_OK;
}
static int write_state(KCS *k) {
    uint8_t s; int e=wait_mask(k,2,0,&s);
    if (e) return e;
    if ((s&0xc0)!=0x80) return K_STATE;
    return drain_dummy(k,s);
}
static int transfer(KCS *k,uint8_t netfn,uint8_t cmd,const uint8_t *data,size_t len,
              uint8_t *out,size_t cap,size_t *used) {
    uint8_t s,b; int e; size_t n=0;
    *used=0;
    if (!out || cap<3) return K_DENIED;
    k->budget=10000; /* <=10 seconds of delayed polling for the whole message. */
    if ((e=status(k,&s))) return e;
    /* Do not abort or take over an interface which is already in use. */
    if ((s&0xc0)!=0 || (s&2)) return K_BUSY;
    if ((e=drain_dummy(k,s))) return e;
    if (k->write(k->ctx,1,0x61)) return K_IO;
    if ((e=write_state(k))) return e;
    for (size_t i=0;i<len+2;i++) {
        if (i==len+1) {
            if (k->write(k->ctx,1,0x62)) return K_IO;
            if ((e=write_state(k))) return e;
        }
        b = i==0 ? (uint8_t)(netfn<<2) : i==1 ? cmd : data[i-2];
        if (k->write(k->ctx,0,b)) return K_IO;
        if (i!=len+1 && (e=write_state(k))) return e;
    }
    for (;;) {
        if ((e=wait_mask(k,2,0,&s))) return e;
        if ((s&0xc0)==0) {
            /* Some BMCs omit the last dummy OBF; never wait for it in IDLE. */
            if ((e=drain_dummy(k,s))) return e;
            *used=n<cap ? n : cap;
            if (n>cap) return K_OVERFLOW;
            if (n<3 || out[0]!=(uint8_t)((netfn+1)<<2) || out[1]!=cmd)
                return K_RESPONSE;
            return K_OK; /* Completion code is out[2], not transport status. */
        }
        if ((s&0xc0)!=0x40) return K_STATE;
        if ((e=wait_mask(k,3,1,&s))) return e;
        if ((s&0xc0)!=0x40) return K_STATE;
        if (k->read(k->ctx,0,&b)) return K_IO;
        if (n<cap) out[n]=b;
        if (++n>512) return K_OVERFLOW;
        if (k->write(k->ctx,0,0x68)) return K_IO;
    }
}
int kcs_query(KCS *k,uint8_t netfn,uint8_t cmd,const uint8_t *data,size_t len,
              uint8_t *out,size_t cap,size_t *used) {
    *used=0;
    if (!allowed(netfn,cmd,data,len)) return K_DENIED;
    return transfer(k,netfn,cmd,data,len,out,cap,used);
}
static const CANDIDATE_STEP candidate[4]={
    {0x90,1,{0x80}},
    {0x94,32,{0x01,1,0x03,1,0x17,1,0x19,1,0x1a,1,0x1b,1,0x1c,1,0x1d,1,
              0x1e,1,0x1f,1,0x20,1,0x21,1,0x22,1,0x23,1,0x24,1,0x29,1}},
    {0x92,2,{0,0}},
    {0x02,1,{1}}
};
const CANDIDATE_STEP *candidate_step(unsigned i) { return i<4 ? &candidate[i] : 0; }
void candidate_arm(KCS *k) { k->candidate_next=0; k->candidate_armed=1; }
void candidate_disarm(KCS *k) { k->candidate_armed=0; }
int candidate_query(KCS *k,unsigned i,uint8_t *out,size_t cap,size_t *used) {
    *used=0;
    if (!k->candidate_armed || i!=k->candidate_next || i>=4) {
        candidate_disarm(k); return K_DENIED;
    }
    /* Consume authorization before touching the device. No automatic replay. */
    candidate_disarm(k);
    const CANDIDATE_STEP *s=&candidate[i];
    int e=transfer(k,0x30,s->command,s->data,s->length,out,cap,used);
    if (!e && *used>=3 && out[2]==0) {
        k->candidate_next=i+1;
        k->candidate_armed=i<3;
    }
    return e;
}
/* B2: 14 ordered packets, only two of which write BMC state. The RPM setter
 * changes index 2 only. Mode/PWM/type are GET-only, preserved and compared.
 * Source 0x62 is the donor logical CHA1 candidate, not yet verified on HERO.
 * No MCU register, duty-cycle, type or control-mode setters are exposed. */
static int bytes_equal(const uint8_t *a,const uint8_t *b,size_t n) {
    for (size_t i=0;i<n;i++) if (a[i]!=b[i]) return 0;
    return 1;
}
void fan_disarm(KCS *k) { k->fan_armed=0; }
void fan_arm(KCS *k) {
    k->fan_next=0; k->fan_armed=1;
    for (unsigned i=0;i<15;i++) k->fan_rpm[i]=k->fan_pwm[i]=k->fan_type[i]=0;
}
int fan_packet(KCS *k,unsigned i,CANDIDATE_STEP *s) {
    static const uint8_t sub[14]={0,1,2,3,1,1,0,2,3,0,0,1,2,3};
    if (!k->fan_armed || i!=k->fan_next || i>=14 || !s) return 0;
    s->command=0x9a; s->length=2; s->data[0]=sub[i]; s->data[1]=0;
    if (i==4) {
        s->length=17; s->data[1]=1;
        for (unsigned j=0;j<15;j++) s->data[j+2]=j==2?0x62:k->fan_rpm[j];
    } else if (i==9) {
        s->command=0x94; s->data[0]=0x20; s->data[1]=1;
    }
    return 1;
}
int fan_query(KCS *k,unsigned i,uint8_t *out,size_t cap,size_t *used) {
    CANDIDATE_STEP s;
    *used=0;
    if (!fan_packet(k,i,&s)) { fan_disarm(k); return K_DENIED; }
    fan_disarm(k); /* Consume before touching the device; never replay. */
    int e=transfer(k,0x30,s.command,s.data,s.length,out,cap,used);
    if (e || out[2]) return e;
    int valid=0;
    if (i==0 || i==6 || i==10) valid=*used==4 && out[3]==0;
    else if (i==9) valid=*used==3;
    else if (*used==18) {
        const uint8_t *r=out+3;
        if (i==1) {
            valid=r[2]==0; /* Existing nonzero mappings require separate review. */
            for (unsigned j=0;j<15;j++) k->fan_rpm[j]=r[j];
        } else if (i==2 || i==3) {
            uint8_t *d=i==2?k->fan_pwm:k->fan_type;
            for (unsigned j=0;j<15;j++) d[j]=r[j];
            valid=1;
        } else if (i==4 || i==5 || i==11) {
            valid=1;
            for (unsigned j=0;j<15;j++) if (r[j]!=(j==2?0x62:k->fan_rpm[j])) valid=0;
        } else if (i==7 || i==12) valid=bytes_equal(r,k->fan_pwm,15);
        else if (i==8 || i==13) valid=bytes_equal(r,k->fan_type,15);
    }
    if (!valid) return K_FAN_VERIFY;
    k->fan_next=i+1; k->fan_armed=i<13;
    return K_OK;
}
int probe_bmc_identity(const uint8_t *p,size_t n) {
    /* Exact Device ID reply from the user's A2 log, not just PCI vendor ID.
     * A BMC update or initialization-in-progress response requires review. */
    static const uint8_t expected[]={0x1c,1,0,0x20,0x81,1,3,2,0xbf,0x3f,0x0a,0,0x93,0x10,0x0d,0,0,0};
    if (!p || n!=sizeof(expected)) return 0;
    for (size_t i=0;i<n;i++) if (p[i]!=expected[i]) return 0;
    return 1;
}
const char *kcs_error(int e) {
    static const char *names[]={"OK","PCI_IO_ERROR","TIMEOUT","INTERFACE_BUSY",
        "KCS_STATE_ERROR","RESPONSE_TOO_LARGE","RESPONSE_HEADER_MISMATCH","COMMAND_DENIED",
        "FAN_RESPONSE_OR_BASELINE_MISMATCH","KCS_STATUS_ALL_FF"};
    return e>=0 && e<10 ? names[e] : "UNKNOWN";
}
static int same(const char *a,const char *b) {
    while (*a && *a==*b) { a++; b++; }
    return *a==*b;
}
int probe_board_gate(const char *board,const char *bios) {
    return same(board,"ROG MAXIMUS Z790 HERO") &&
        (same(bios,"3001") || same(bios,"3107"));
}
int probe_pci_layout(const uint8_t c[64]) {
    uint32_t bar1=(uint32_t)c[20] | ((uint32_t)c[21]<<8) |
                  ((uint32_t)c[22]<<16) | ((uint32_t)c[23]<<24);
    uint32_t bar0=(uint32_t)c[16] | ((uint32_t)c[17]<<8) |
                  ((uint32_t)c[18]<<16) | ((uint32_t)c[19]<<24);
    return c[0]==3 && c[1]==0x1a && c[2]==2 && c[3]==0x24 &&
        c[8]==1 && (c[14]&0x7f)==0 &&
        /* BAR1 must not be the upper half of a 64-bit BAR0. */
        (bar0&7)!=4 && (bar1&7)==0 && (bar1&0xfffffff0U)!=0 &&
        (bar1&0xfffffff0U)!=0xfffffff0U;
}
int probe_pci_gate(const uint8_t c[64]) {
    return probe_pci_layout(c) && (c[4]&2);
}
int probe_sensor(const uint8_t *record,size_t n,SENSOR *s) {
    if (n<5 || n<5U+record[4] || (record[3]!=1 && record[3]!=2)) return 0;
    const uint8_t *p=record+5;
    size_t len=record[4], code=record[3]==1 ? 42 : 26;
    if (len<=code) return 0;
    s->owner=p[0]; s->lun=p[1]; s->number=p[2]; s->type=p[7];
    s->event_type=p[8];
    s->share_count=record[3]==2 ? p[18]&15 : 0;
    size_t chars=p[code]&31;
    if (chars>len-code-1) return 0;
    if ((p[code]&0xc0)!=0xc0) {
        const char *unknown="[non-ASCII; see raw SDR]";
        for (size_t i=0;;i++) { s->name[i]=unknown[i]; if (!unknown[i]) break; }
    } else {
        for (size_t i=0;i<chars;i++) {
            uint8_t c=p[code+1+i]; s->name[i]=c>=32 && c<=126 ? (char)c : '?';
        }
        s->name[chars]=0;
    }
    return 1;
}
