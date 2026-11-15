#ifndef HERO_BMC_PCI_H
#define HERO_BMC_PCI_H
/* Shared R5/S22 target policy. PCI bus assignment is firmware dependent.
 * Evidence: .71 bus04 and .15 bus74 use the same ASPEED management identity.
 * No BAR sizing writes, no raw MMIO, no protocol attribute changes. */
static int hero_bmc_pci_identity(const uint8_t c[64]){
    return c && probe_pci_layout(c) && c[9]==1 && c[10]==7 && c[11]==0x0c &&
        u32(c+44)==0x24021a03U;
}
static int hero_bmc_pci_location(UN segment,UN bus,UN device,UN function){
    return segment==0 && bus<=255 && device==1 && function==0;
}
static int hero_bmc_pci_bar1(const uint8_t *r,const uint8_t c[64]){
    if(!r||!c||r[0]!=0x8a||u16(r+1)!=43||r[3]!=0)return 0;
    uint64_t base=u64(r+14),length=u64(r+38);
    return base==(u32(c+20)&0xfffffff0U) && length>=0xe8d &&
        base<0x100000000ULL && length<=0x100000000ULL-base;
}
#endif
