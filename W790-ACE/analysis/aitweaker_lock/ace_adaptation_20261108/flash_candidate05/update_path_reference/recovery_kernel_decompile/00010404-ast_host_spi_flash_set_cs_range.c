
void ast_host_spi_flash_set_cs_range(void)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = __gnu_mcount_nc();
  uVar2 = *(uint *)(_LANCHOR1 + 0x30);
  DataSynchronizationBarrier(0xf);
  printk("[%s] 0x%08X\n",DAT_00010484,iVar1 + -0x100000);
  DataSynchronizationBarrier(0xe);
  *(uint *)(_LANCHOR1 + 0x30) = uVar2 & 0xf00fffff | 0x1f00000;
  DataSynchronizationBarrier(0xf);
  DataSynchronizationBarrier(0xe);
  *(uint *)(_LANCHOR1 + 0x34) = *(uint *)(_LANCHOR1 + 0x34) & 0xf00ff00f | 0x3f00200;
  return;
}

