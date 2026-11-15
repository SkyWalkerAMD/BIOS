/* Bounds-checked parsers; inputs are in-memory images and exported HII packages.
 * These routines do not execute or modify any firmware data. */
#include "probe_core.h"
static uint16_t u16(const uint8_t *p) { return p[0]|((uint16_t)p[1]<<8); }
static uint32_t u32(const uint8_t *p) { return u16(p)|((uint32_t)u16(p+2)<<16); }
uint32_t probe_crc32(const void *data,size_t n) {
    const uint8_t *p=data; uint32_t crc=0xffffffffU;
    while (n--) {
        crc^=*p++;
        for (unsigned k=0;k<8;k++) crc=(crc>>1)^(0xedb88320U & (0U-(crc&1)));
    }
    return ~crc;
}
int probe_image(const void *data,size_t n,IMAGE_INFO *out) {
    const uint8_t *p=data; *out=(IMAGE_INFO){0};
    if (!p || n<0x40 || n>0x40000000 || u16(p)!=0x5a4d) return 0;
    size_t pe=u32(p+0x3c);
    if (pe>n || n-pe<0x18 || u32(p+pe)!=0x4550 || u16(p+pe+4)!=0x8664) return 0;
    unsigned count=u16(p+pe+6),opts=u16(p+pe+20);
    size_t opt=pe+24;
    if (!count || count>96 || opts<0x70 || opts>n-opt || u16(p+opt)!=0x20b) return 0;
    size_t table=opt+opts;
    if (count>(n-table)/40) return 0;
    out->entry=u32(p+opt+16);out->image_size=u32(p+opt+56);
    if (out->image_size>n || out->entry>=out->image_size) return 0;
    for (unsigned i=0;i<count;i++) {
        const uint8_t *s=p+table+i*40;
        if (s[0]!='.'||s[1]!='t'||s[2]!='e'||s[3]!='x'||s[4]!='t'||s[5]) continue;
        size_t size=u32(s+8),rva=u32(s+12);
        if (!size || rva>out->image_size || size>out->image_size-rva) return 0;
        out->text_rva=(uint32_t)rva;out->text_size=(uint32_t)size;
        out->text_crc=probe_crc32(p+rva,size);
        return 1;
    }
    return 0;
}
int probe_hii(const void *data,size_t n,HII_INFO *out) {
    const uint8_t *p=data; *out=(HII_INFO){0};
    if (!p || n<20 || u32(p+16)!=n) return 0;
    size_t pos=20;
    int end_seen=0;
    while (pos<n) {
        if (n-pos<4) return 0;
        uint32_t header=u32(p+pos),len=header&0xffffff,type=header>>24;
        if (len<4 || len>n-pos || end_seen) return 0;
        out->packages++;
        if (type==2) {
            size_t cur=pos+4,end=pos+len; unsigned depth=0; int setup=0;
            /* Main Setup formset GUID: 7B59104A-C00D-4158-87FF-F04D6396A915 */
            static const uint8_t setup_guid[16]={0x4a,0x10,0x59,0x7b,0x0d,0xc0,0x58,0x41,0x87,0xff,0xf0,0x4d,0x63,0x96,0xa9,0x15};
            while (cur<end) {
                if (end-cur<2) return 0;
                uint8_t op=p[cur],len2=p[cur+1]&127;
                if (len2<2 || len2>end-cur) return 0;
                if (op==14) {
                    if (len2<23 || depth!=0 || !(p[cur+1]&128)) return 0;
                    out->formsets++;setup=1;
                    for (unsigned k=0;k<16;k++) if (p[cur+2+k]!=setup_guid[k]) setup=0;
                }
                if (op==1) {
                    if (len2!=6) return 0;
                    out->forms++;
                    if (setup && u16(p+cur+2)==0x2714) out->form_2714++;
                    if (setup && u16(p+cur+2)==0x2713) out->form_2713++;
                }
                if (op==8) { if (len2<17) return 0; out->password_questions++; }
                if (op==41) {
                    if (len2!=2 || !depth || (p[cur+1]&128)) return 0;
                    if (--depth==0) setup=0;
                } else if (p[cur+1]&128) {
                    if (++depth>256) return 0;
                }
                cur+=len2;
            }
            if (depth) return 0;
        }
        if (type==0xdf) { if (len!=4) return 0; end_seen=1; }
        pos+=len;
    }
    return end_seen;
}
