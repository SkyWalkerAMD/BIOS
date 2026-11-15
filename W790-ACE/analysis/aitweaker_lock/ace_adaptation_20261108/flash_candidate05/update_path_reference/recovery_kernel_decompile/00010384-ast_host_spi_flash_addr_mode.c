
undefined4 ast_host_spi_flash_addr_mode(void)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = __gnu_mcount_nc();
  DataSynchronizationBarrier(0xf);
  if (iVar1 == 1) {
    uVar2 = *(uint *)(_LANCHOR1 + 4) | 3;
  }
  else {
    uVar2 = *(uint *)(_LANCHOR1 + 4) & 0xfffffffc;
  }
  DataSynchronizationBarrier(0xe);
  *(uint *)(_LANCHOR1 + 4) = uVar2;
  return 0;
}

