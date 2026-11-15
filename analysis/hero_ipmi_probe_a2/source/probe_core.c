/* Independent, bounded implementation of the standard IPMI KCS handshake.
 * The only IPMI commands allowed here are standard retrieval commands.
 * No OEM commands, reset, erase, SDR reservation, PCI config or flash writes. */
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
    if (*s==255) return K_IO;
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
int kcs_query(KCS *k,uint8_t netfn,uint8_t cmd,const uint8_t *data,size_t len,
              uint8_t *out,size_t cap,size_t *used) {
    uint8_t s,b; int e; size_t n=0;
    *used=0;
    if (!allowed(netfn,cmd,data,len) || !out || cap<3) return K_DENIED;
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
const char *kcs_error(int e) {
    static const char *names[]={"OK","PCI_IO_ERROR","TIMEOUT","INTERFACE_BUSY",
        "KCS_STATE_ERROR","RESPONSE_TOO_LARGE","RESPONSE_HEADER_MISMATCH","COMMAND_DENIED"};
    return e>=0 && e<8 ? names[e] : "UNKNOWN";
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
