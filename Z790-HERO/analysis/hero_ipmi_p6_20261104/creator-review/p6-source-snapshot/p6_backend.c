#include "p6_backend.h"

/* No firmware globals, dynamic allocation, hardware I/O or libc calls. */
typedef struct {
    const P6_IO *io;
    P6_RESULT *r;
    unsigned stage, status, cc, blocked;
} WORK;
typedef struct { uint8_t source, ip[4], mask[4], gw[4]; } LAN_STATE;
typedef struct { uint8_t use, action, pre, flags; uint16_t initial, left; } WDT;

static void zero(void *v, size_t n) { uint8_t *p=v; while(n--) *p++=0; }
static void copy(void *v, const void *s, size_t n) {
    uint8_t *p=v; const uint8_t *q=s; while(n--) *p++=*q++;
}
static int equal(const void *v,const void *s,size_t n) {
    const uint8_t *p=v,*q=s; while(n--) if(*p++!=*q++) return 0; return 1;
}
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0]|((uint16_t)p[1]<<8)); }
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static int begin(WORK *w,const P6_IO *io,P6_RESULT *r) {
    zero(w,sizeof(*w)); w->io=io; w->r=r;
    if(!r) return 0;
    zero(r,sizeof(*r));
    if(!io||!io->exchange) { r->status=r->cause=P6_ARGUMENT; return 0; }
    return 1;
}
static int failure(WORK *w,unsigned status) { w->status=status; return 0; }
static int malformed(WORK *w) { w->blocked=1; return failure(w,P6_PROTOCOL); }
static int finish(WORK *w,int success) {
    w->r->status=success?P6_OK:w->status;
    w->r->cause=success?P6_OK:w->status;
    w->r->stage=w->stage; w->r->completion=success?0:w->cc;
    return (int)w->r->status;
}
static unsigned cc_status(uint8_t nf,uint8_t cmd,uint8_t cc) {
    if(cc==0xc0||cc==0xc5) return P6_BUSY;
    if(cc==0xc1||cc==0xc2) return P6_UNSUPPORTED;
    if(nf==0x0c && (cmd==1||cmd==2)) {
        if(cc==0x80||cc==0x82) return P6_UNSUPPORTED;
        if(cc==0x81) return P6_BUSY;
    }
    if(nf==0x0a && cmd>=0x40 && cmd<=0x47) {
        if(cc==0x81) return P6_BUSY;
        if(cc==0x80) return P6_UNSUPPORTED;
    }
    return P6_COMPLETION;
}
/* A malformed or transport-failed response permanently blocks this operation.
 * Exact successful lengths avoid interpreting unknown layouts as known ones.
 */
static int command(WORK *w,uint8_t nf,uint8_t cmd,const uint8_t *req,size_t n,
                   uint8_t *payload,size_t want,int write) {
    uint8_t response[64]; size_t len=sizeof(response);
    if(w->blocked) return 0;
    w->status=P6_OK; w->cc=0;
    w->r->requests++;
    if(write) w->r->writes++;
    if(w->io->exchange(w->io->context,nf,cmd,req,n,response,&len)) {
        w->blocked=1; return failure(w,P6_TRANSPORT);
    }
    if(len<3||len>sizeof(response)||response[0]!=(uint8_t)((nf+1U)<<2)||response[1]!=cmd)
        return malformed(w);
    if(response[2]) {
        if(len!=3) return malformed(w);
        w->cc=response[2]; return failure(w,cc_status(nf,cmd,response[2]));
    }
    if(len!=want+3) return malformed(w);
    if(want) copy(payload,response+3,want);
    return 1;
}

static int unicast(uint32_t x) {
    unsigned first=x>>24;
    return x!=0 && x!=0xffffffffU && first!=0 && first!=127 && first<224;
}
int p6_validate_ipv4(const uint8_t ip[4],const uint8_t mask[4],const uint8_t gw[4]) {
    uint32_t a,m,g,h;
    if(!ip||!mask||!gw) return 0;
    a=be32(ip); m=be32(mask); g=be32(gw); h=~m;
    /* /1..30 only: /31,/32 host semantics differ from a BMC LAN gateway. */
    if(!unicast(a)||!m||h<3||((h+1U)&h)!=0) return 0;
    if((a&h)==0||(a&h)==h) return 0;
    if(g && (!unicast(g)||g==a||(g&m)!=(a&m)||(g&h)==0||(g&h)==h)) return 0;
    return 1;
}
static int lan_get(WORK *w,uint8_t channel,uint8_t selector,uint8_t *out,size_t n) {
    uint8_t req[4]={channel,selector,0,0},p[5];
    if(!command(w,0x0c,2,req,sizeof(req),p,n+1,0)) return 0;
    /* Layout version 1 supported; high nibble is present version, low oldest. */
    if((p[0]>>4)<1||(p[0]&15)>1) return malformed(w);
    copy(out,p+1,n); return 1;
}
static int lan_set(WORK *w,uint8_t channel,uint8_t selector,const uint8_t *p,size_t n) {
    uint8_t req[6]={channel,selector,0,0,0,0};
    if(n>4) return failure(w,P6_ARGUMENT);
    copy(req+2,p,n); return command(w,0x0c,1,req,n+2,0,0,1);
}
static int sip_read(WORK *w,uint8_t c,uint8_t *state) {
    if(!lan_get(w,c,0,state,1)) return 0;
    if(*state>2) return malformed(w);
    return 1;
}
static int sip_set(WORK *w,uint8_t c,uint8_t state) { return lan_set(w,c,0,&state,1); }
static int lan_snapshot(WORK *w,uint8_t c,LAN_STATE *s) {
    if(!lan_get(w,c,4,&s->source,1)) return 0;
    if(s->source>4) return malformed(w);
    if(!lan_get(w,c,3,s->ip,4)||!lan_get(w,c,6,s->mask,4)||!lan_get(w,c,12,s->gw,4)) return 0;
    return 1;
}
static int channel_info(WORK *w,uint8_t c,int *lan) {
    uint8_t p[9]; *lan=0;
    if(!command(w,6,0x42,&c,1,p,sizeof(p),0)) return 0;
    if(p[0]!=c||(p[1]&0x80)||(p[2]&0xe0)) return malformed(w);
    *lan=(p[1]==4); return 1;
}
static int choose_channel(WORK *w,uint8_t requested,uint8_t *found) {
    int lan; unsigned count=0;
    w->stage=P6_STAGE_CHANNEL;
    if(requested) {
        if(!channel_info(w,requested,&lan)) return 0;
        if(!lan) return failure(w,P6_ARGUMENT);
        *found=requested; w->r->channel=requested; return 1;
    }
    for(uint8_t c=1;c<=11;c++) {
        if(!channel_info(w,c,&lan)) {
            /* Invalid channel only; other errors cannot establish uniqueness. */
            if(!w->blocked && w->cc==0xcc) continue;
            return 0;
        }
        if(lan) { *found=c; count++; }
    }
    if(count!=1) return failure(w,count?P6_ARGUMENT:P6_UNSUPPORTED);
    w->r->channel=*found; return 1;
}
static int lan_same(const LAN_STATE *a,const LAN_STATE *b) {
    if(a->source!=b->source) return 0;
    /* Dynamic addresses are a lease, not persistent static settings. */
    return a->source==2 || (equal(a->ip,b->ip,4)&&equal(a->mask,b->mask,4)&&equal(a->gw,b->gw,4));
}
static int lan_write_state(WORK *w,uint8_t c,const LAN_STATE *s) {
    if(!lan_set(w,c,4,&s->source,1)) return 0;
    if(s->source==2) return 1;
    return lan_set(w,c,3,s->ip,4)&&lan_set(w,c,6,s->mask,4)&&lan_set(w,c,12,s->gw,4);
}
static int lan_verify(WORK *w,uint8_t c,const LAN_STATE *s) {
    LAN_STATE actual; uint8_t sip;
    if(!sip_read(w,c,&sip)) return 0;
    if(sip!=0) return failure(w,P6_BUSY);
    if(!lan_snapshot(w,c,&actual)) return 0;
    if(!lan_same(&actual,s)) return failure(w,P6_VERIFY);
    return 1;
}
static int lan_recover(WORK *w,uint8_t c,const LAN_STATE *old,int held,int committed) {
    uint8_t state;
    if(!sip_read(w,c,&state)) return 0;
    if(held) {
        if(state!=1) return failure(w,P6_BUSY);
    } else {
        if(state!=0) return failure(w,P6_BUSY);
        if(!sip_set(w,c,1)||!sip_read(w,c,&state)) return 0;
        if(state!=1) return failure(w,P6_VERIFY);
    }
    if(!lan_write_state(w,c,old)) return 0;
    if(!sip_set(w,c,2)) {
        /* Commit Write is optional. Only a known rejection of that value may
         * fall through to Complete during recovery of an uncommitted change.
         * Complete can either retain the restored values or discard staging;
         * the final reads decide, never the response alone.
         */
        if(w->blocked||committed||(w->cc!=0x80&&w->cc!=0xcc)) return 0;
    }
    if(!sip_set(w,c,0)) return 0;
    return lan_verify(w,c,old);
}
static int recovery_finish(WORK *w,unsigned cause,unsigned stage,unsigned cc,int ok,unsigned recovered) {
    w->r->recovery=ok?recovered:P6_RECOVERY_UNCONFIRMED;
    w->r->recovery_cause=ok?P6_OK:w->status;
    w->r->recovery_completion=ok?0:w->cc;
    w->r->cause=cause; w->r->stage=stage; w->r->completion=cc;
    w->r->status=ok?cause:P6_UNCERTAIN;
    return (int)w->r->status;
}
int p6_lan_apply(const P6_IO *io,const P6_LAN *cfg,P6_RESULT *r) {
    WORK w; LAN_STATE old,wanted; uint8_t c=0,state; int held=0,committed=0;
    if(!begin(&w,io,r)) return P6_ARGUMENT;
    if(!cfg||cfg->source>2||cfg->channel>11) { failure(&w,P6_ARGUMENT); return finish(&w,0); }
    if(!cfg->source) { r->flags=P6_FLAG_NO_CHANGE; return finish(&w,1); }
    if(cfg->source==1&&!p6_validate_ipv4(cfg->address,cfg->mask,cfg->gateway)) {
        failure(&w,P6_ARGUMENT); return finish(&w,0);
    }
    if(!choose_channel(&w,cfg->channel,&c)) return finish(&w,0);
    w.stage=P6_STAGE_SNAPSHOT;
    if(!sip_read(&w,c,&state)) return finish(&w,0);
    if(state) { failure(&w,P6_BUSY); return finish(&w,0); }
    if(!lan_snapshot(&w,c,&old)) return finish(&w,0);
    if((old.source!=1&&old.source!=2)||(old.source==1&&!p6_validate_ipv4(old.ip,old.mask,old.gw))) {
        failure(&w,P6_UNSUPPORTED); return finish(&w,0);
    }
    wanted.source=cfg->source; copy(wanted.ip,cfg->address,4);
    copy(wanted.mask,cfg->mask,4); copy(wanted.gw,cfg->gateway,4);
    if(lan_same(&old,&wanted)) { r->flags=P6_FLAG_NO_CHANGE; return finish(&w,1); }
    /* Recheck SIP after the snapshot, immediately before the mutation. */
    w.stage=P6_STAGE_ACQUIRE;
    if(!sip_read(&w,c,&state)) return finish(&w,0);
    if(state) { failure(&w,P6_BUSY); return finish(&w,0); }
    if(!sip_set(&w,c,1)) {
        if(!w.blocked) return finish(&w,0);
        goto uncertain;
    }
    held=1;
    if(!sip_read(&w,c,&state)) goto failed;
    if(state!=1) { failure(&w,P6_VERIFY); goto failed; }
    w.stage=P6_STAGE_WRITE;
    if(!lan_write_state(&w,c,&wanted)) goto failed;
    w.stage=P6_STAGE_COMMIT;
    if(!sip_set(&w,c,2)) goto failed;
    committed=1;
    w.stage=P6_STAGE_COMPLETE;
    if(!sip_set(&w,c,0)) goto failed;
    held=0;
    w.stage=P6_STAGE_VERIFY;
    if(!lan_verify(&w,c,&wanted)) goto failed;
    if(cfg->source==2) r->flags|=P6_FLAG_DHCP_LEASE_DYNAMIC;
    return finish(&w,1);
failed:
    if(!w.blocked) {
        unsigned cause=w.status,stage=w.stage,cc=w.cc;
        w.stage=P6_STAGE_ROLLBACK;
        int ok=lan_recover(&w,c,&old,held,committed);
        if(old.source==2) r->flags|=P6_FLAG_DHCP_LEASE_DYNAMIC;
        return recovery_finish(&w,cause,stage,cc,ok,P6_RECOVERY_RESTORED);
    }
uncertain:
    return recovery_finish(&w,w.status,w.stage,w.cc,0,P6_RECOVERY_RESTORED);
}

static int watchdog_get(WORK *w,WDT *t) {
    uint8_t p[8];
    if(!command(w,6,0x25,0,0,p,sizeof(p),0)) return 0;
    if((p[0]&0x38)||(p[0]&7)>5||(p[1]&0x88)||(p[1]&7)>3||((p[1]>>4)&7)>3||(p[3]&0xc1))
        return malformed(w);
    t->use=p[0]; t->action=p[1]; t->pre=p[2]; t->flags=p[3];
    t->initial=le16(p+4); t->left=le16(p+6);
    return 1;
}
static int watchdog_owned(WORK *w,const WDT *t) {
    if((t->use&0x40)&&(t->use&7)!=3) return failure(w,P6_FOREIGN_OWNER);
    return 1;
}
static int watchdog_set(WORK *w,const WDT *t,int clear_own_flag) {
    uint8_t p[6]={(uint8_t)(t->use&0x87),t->action,t->pre,
                  (uint8_t)(clear_own_flag?8:0),(uint8_t)t->initial,(uint8_t)(t->initial>>8)};
    return command(w,6,0x24,p,sizeof(p),0,0,1);
}
static int watchdog_prepared(const WDT *t,unsigned min,unsigned action) {
    return (t->use&0xbf)==3&&t->action==action&&!t->pre&&t->initial==min*600U;
}
static int watchdog_stop_owned(WORK *w) {
    WDT t,after;
    if(!watchdog_get(w,&t)) return 0;
    if((t.use&7)!=3) return failure(w,P6_FOREIGN_OWNER);
    if(t.use&0x40) {
        if(!watchdog_set(w,&t,0)||!watchdog_get(w,&after)) return 0;
        if((after.use&7)!=3||(after.use&0x40)) return failure(w,P6_VERIFY);
    }
    return 1;
}
static int watchdog_failed(WORK *w) {
    unsigned cause=w->status,stage=w->stage,cc=w->cc;
    if(w->blocked) return recovery_finish(w,cause,stage,cc,0,P6_RECOVERY_STOPPED);
    w->stage=P6_STAGE_ROLLBACK;
    int ok=watchdog_stop_owned(w);
    return recovery_finish(w,cause,stage,cc,ok,P6_RECOVERY_STOPPED);
}
int p6_watchdog_configure(const P6_IO *io,int enabled,unsigned minutes,unsigned action,P6_RESULT *r) {
    WORK w; WDT old,wanted,after;
    if(!begin(&w,io,r)) return P6_ARGUMENT;
    if((enabled!=0&&enabled!=1)||(enabled&&(minutes<1||minutes>30||action>3))) {
        failure(&w,P6_ARGUMENT); return finish(&w,0);
    }
    w.stage=P6_STAGE_SNAPSHOT;
    if(!watchdog_get(&w,&old)||!watchdog_owned(&w,&old)) return finish(&w,0);
    if(!enabled) {
        if((old.use&7)!=3||!(old.use&0x40)) { r->flags=P6_FLAG_NO_CHANGE; return finish(&w,1); }
        wanted=old;
    } else {
        wanted=(WDT){3,(uint8_t)action,0,0,(uint16_t)(minutes*600U),0};
        if(!(old.use&0x40)&&watchdog_prepared(&old,minutes,action)) {
            r->flags=P6_FLAG_NO_CHANGE; return finish(&w,1);
        }
    }
    w.stage=P6_STAGE_WRITE;
    if(!watchdog_set(&w,&wanted,enabled)) return watchdog_failed(&w);
    w.stage=P6_STAGE_VERIFY;
    if(!watchdog_get(&w,&after)) return watchdog_failed(&w);
    if(after.use&0x40 || (enabled?!watchdog_prepared(&after,minutes,action):
       ((after.use&0xbf)!=(old.use&0xbf)||after.action!=old.action||after.pre!=old.pre||after.initial!=old.initial))) {
        failure(&w,P6_VERIFY); return watchdog_failed(&w);
    }
    return finish(&w,1);
}
int p6_watchdog_start(const P6_IO *io,unsigned minutes,unsigned action,P6_RESULT *r) {
    WORK w; WDT before,after;
    if(!begin(&w,io,r)) return P6_ARGUMENT;
    if(minutes<1||minutes>30||action>3) { failure(&w,P6_ARGUMENT); return finish(&w,0); }
    w.stage=P6_STAGE_SNAPSHOT;
    if(!watchdog_get(&w,&before)||!watchdog_owned(&w,&before)) return finish(&w,0);
    if(!watchdog_prepared(&before,minutes,action)) { failure(&w,P6_VERIFY); return finish(&w,0); }
    if(before.use&0x40) {
        if(!before.left||before.left>before.initial) { failure(&w,P6_VERIFY); return finish(&w,0); }
        r->flags=P6_FLAG_NO_CHANGE; return finish(&w,1);
    }
    w.stage=P6_STAGE_START;
    if(!command(&w,6,0x22,0,0,0,0,1)) return watchdog_failed(&w);
    w.stage=P6_STAGE_VERIFY;
    if(!watchdog_get(&w,&after)) return watchdog_failed(&w);
    if(!watchdog_prepared(&after,minutes,action)||!(after.use&0x40)||!after.left||after.left>after.initial) {
        failure(&w,P6_VERIFY); return watchdog_failed(&w);
    }
    return finish(&w,1);
}

static int sel_info(WORK *w,P6_SEL_INFO *info) {
    uint8_t p[14];
    if(!command(w,0x0a,0x40,0,0,p,sizeof(p),0)) return 0;
    if(p[0]!=0x51||(p[13]&0x70)) return malformed(w);
    info->version=p[0]; info->entries=le16(p+1); info->free_bytes=le16(p+3);
    info->last_add=le32(p+5); info->last_erase=le32(p+9); info->operations=p[13]; return 1;
}
int p6_sel_get_info(const P6_IO *io,P6_SEL_INFO *info,P6_RESULT *r) {
    WORK w;
    if(!begin(&w,io,r)) return P6_ARGUMENT;
    if(!info) { failure(&w,P6_ARGUMENT); return finish(&w,0); }
    zero(info,sizeof(*info)); w.stage=P6_STAGE_SNAPSHOT;
    return finish(&w,sel_info(&w,info));
}
static int sel_reserve(WORK *w,uint16_t *reservation) {
    uint8_t p[2];
    if(!command(w,0x0a,0x42,0,0,p,2,0)) return 0;
    *reservation=le16(p);
    if(!*reservation) return malformed(w);
    return 1;
}
static int sel_info_same(const P6_SEL_INFO *a,const P6_SEL_INFO *b) {
    return a->entries==b->entries&&a->last_add==b->last_add&&a->last_erase==b->last_erase&&a->operations==b->operations;
}
static int destructive_failed(WORK *w) {
    unsigned cause=w->status;
    finish(w,0); w->r->status=P6_UNCERTAIN; w->r->cause=cause;
    w->r->recovery=P6_RECOVERY_UNCONFIRMED; return P6_UNCERTAIN;
}
int p6_sel_clear(const P6_IO *io,P6_RESULT *r) {
    WORK w; P6_SEL_INFO before,check,after; uint16_t reservation; uint8_t p,req[6];
    if(!begin(&w,io,r)) return P6_ARGUMENT;
    if(!io->delay_ms) { failure(&w,P6_ARGUMENT); return finish(&w,0); }
    w.stage=P6_STAGE_SNAPSHOT;
    if(!sel_info(&w,&before)) return finish(&w,0);
    if(!before.entries) { r->flags=P6_FLAG_NO_CHANGE; return finish(&w,1); }
    if(!(before.operations&2)) { failure(&w,P6_UNSUPPORTED); return finish(&w,0); }
    w.stage=P6_STAGE_RESERVE;
    if(!sel_reserve(&w,&reservation)||!sel_info(&w,&check)) return finish(&w,0);
    if(!sel_info_same(&before,&check)) { failure(&w,P6_BUSY); return finish(&w,0); }
    req[0]=(uint8_t)reservation; req[1]=(uint8_t)(reservation>>8);
    req[2]='C'; req[3]='L'; req[4]='R'; req[5]=0xaa;
    w.stage=P6_STAGE_WRITE;
    if(!command(&w,0x0a,0x47,req,6,&p,1,1)) {
        if(w.blocked) return destructive_failed(&w);
        return finish(&w,0);
    }
    if(p>1) { malformed(&w); return destructive_failed(&w); }
    req[5]=0; w.stage=P6_STAGE_POLL;
    while(p==0&&r->polls<30) {
        if(io->delay_ms(io->context,1000)) { failure(&w,P6_TIMEOUT); return destructive_failed(&w); }
        r->polls++;
        if(!command(&w,0x0a,0x47,req,6,&p,1,0)) return destructive_failed(&w);
        if(p>1) { malformed(&w); return destructive_failed(&w); }
    }
    if(!p) { failure(&w,P6_TIMEOUT); return destructive_failed(&w); }
    r->flags|=P6_FLAG_ERASE_COMPLETED;
    w.stage=P6_STAGE_VERIFY;
    if(!sel_info(&w,&after)) return destructive_failed(&w);
    r->entries_after=after.entries;
    /* Events arriving after erasure are not removed with a second clear. */
    return finish(&w,1);
}
int p6_sel_delete_oldest(const P6_IO *io,P6_RESULT *r) {
    WORK w; P6_SEL_INFO before,after; uint16_t reservation,id; uint8_t p[18],req[6],reply[2];
    if(!begin(&w,io,r)) return P6_ARGUMENT;
    w.stage=P6_STAGE_SNAPSHOT;
    if(!sel_info(&w,&before)) return finish(&w,0);
    if(!before.entries) { r->flags=P6_FLAG_NO_CHANGE; return finish(&w,1); }
    if((before.operations&10)!=10) { failure(&w,P6_UNSUPPORTED); return finish(&w,0); }
    w.stage=P6_STAGE_RESERVE;
    if(!sel_reserve(&w,&reservation)) return finish(&w,0);
    req[0]=(uint8_t)reservation; req[1]=(uint8_t)(reservation>>8);
    req[2]=req[3]=req[4]=0; req[5]=255;
    if(!command(&w,0x0a,0x43,req,6,p,18,0)) return finish(&w,0);
    id=le16(p+2);
    if(!id||id==0xffff||le16(p)==0||le16(p)==id) { malformed(&w); return finish(&w,0); }
    r->record_id=id;
    req[2]=(uint8_t)id; req[3]=(uint8_t)(id>>8);
    w.stage=P6_STAGE_WRITE;
    if(!command(&w,0x0a,0x46,req,4,reply,2,1)) {
        if(w.blocked) return destructive_failed(&w);
        return finish(&w,0);
    }
    if(le16(reply)!=id) { malformed(&w); return destructive_failed(&w); }
    r->flags|=P6_FLAG_RECORD_DELETED;
    w.stage=P6_STAGE_VERIFY;
    /* Delete cancels the reservation. A full, offset-zero read permits zero. */
    req[0]=req[1]=0;
    if(command(&w,0x0a,0x43,req,6,p,18,0)) {
        failure(&w,P6_VERIFY); return destructive_failed(&w);
    }
    if(w.blocked||w.cc!=0xcb) return destructive_failed(&w);
    if(!sel_info(&w,&after)) return destructive_failed(&w);
    r->entries_after=after.entries;
    return finish(&w,1);
}

static int logging_get(WORK *w,uint8_t *v) {
    if(!command(w,6,0x2f,0,0,v,1,0)) return 0;
    if(*v&0x10) return malformed(w);
    return 1;
}
static int logging_restore(WORK *w,uint8_t old) {
    uint8_t current,wanted,after;
    if(!logging_get(w,&current)) return 0;
    wanted=(uint8_t)((current&~8U)|(old&8));
    if(wanted!=current && !command(w,6,0x2e,&wanted,1,0,0,1)) return 0;
    if(!logging_get(w,&after)) return 0;
    if(after!=wanted) return failure(w,P6_VERIFY);
    return 1;
}
int p6_sel_logging(const P6_IO *io,int enabled,P6_RESULT *r) {
    WORK w; uint8_t old,wanted,after;
    if(!begin(&w,io,r)) return P6_ARGUMENT;
    if(enabled!=0&&enabled!=1) { failure(&w,P6_ARGUMENT); return finish(&w,0); }
    w.stage=P6_STAGE_SNAPSHOT;
    if(!logging_get(&w,&old)) return finish(&w,0);
    wanted=(uint8_t)((old&~8U)|(enabled?8:0));
    if(wanted==old) { r->flags=P6_FLAG_NO_CHANGE; return finish(&w,1); }
    w.stage=P6_STAGE_WRITE;
    if(!command(&w,6,0x2e,&wanted,1,0,0,1)) {
        if(w.blocked) return destructive_failed(&w);
        return finish(&w,0);
    }
    w.stage=P6_STAGE_VERIFY;
    if(!logging_get(&w,&after)) return destructive_failed(&w);
    if(after!=wanted) {
        unsigned cc=0; failure(&w,P6_VERIFY); w.stage=P6_STAGE_ROLLBACK;
        int ok=logging_restore(&w,old);
        return recovery_finish(&w,P6_VERIFY,P6_STAGE_VERIFY,cc,ok,P6_RECOVERY_RESTORED);
    }
    return finish(&w,1);
}
