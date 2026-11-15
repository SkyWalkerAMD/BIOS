
undefined4 hostspiflash_configure_clock(void)

{
  undefined4 uVar1;
  uint uVar2;
  uint uVar3;
  
  uVar1 = __gnu_mcount_nc();
  uVar2 = __aeabi_uidiv(200000000,uVar1);
  uVar3 = (uVar2 & 0xff) >> 4;
  DataSynchronizationBarrier(0xf);
  uVar2 = (uint)*(byte *)((int)&DAT_00011ab8 + uVar2 + uVar3 * -0x10 + 3) << 8 | uVar3 << 0x18;
  DataSynchronizationBarrier(0xe);
  *(uint *)(_LANCHOR1 + 0x10) = uVar2 | *(uint *)(_LANCHOR1 + 0x10) & 0xf00ff0ff;
  DataSynchronizationBarrier(0xf);
  DataSynchronizationBarrier(0xe);
  *(uint *)(_LANCHOR1 + 0x14) = uVar2 | *(uint *)(_LANCHOR1 + 0x14) & 0xf00ff0ff;
  return 0;
}

