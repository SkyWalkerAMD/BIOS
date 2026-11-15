
undefined4 ast_host_spi_flash_transfer(void)

{
  undefined1 *puVar1;
  int iVar2;
  int iVar3;
  int extraout_r2;
  uint extraout_r3;
  uint uVar4;
  uint uVar5;
  undefined8 uVar6;
  int in_stack_00000000;
  
  uVar6 = __gnu_mcount_nc();
  iVar2 = (int)((ulonglong)uVar6 >> 0x20);
  DataSynchronizationBarrier(0xf);
  DataSynchronizationBarrier(0xe);
  *(uint *)(_LANCHOR1 + ce_index * 4 + 0x10) =
       *(uint *)(_LANCHOR1 + ce_index * 4 + 0x10) & 0xfffffff8 | 3;
  if (iVar2 != 0) {
    puVar1 = (undefined1 *)((int)uVar6 + -1);
    do {
      puVar1 = puVar1 + 1;
      DataSynchronizationBarrier(0xe);
      *(undefined1 *)(&DAT_000126cc)[ce_index] = *puVar1;
    } while ((undefined1 *)((int)uVar6 + iVar2 + -1) != puVar1);
  }
  uVar4 = extraout_r3;
  if (0xffff < extraout_r3) {
    uVar4 = 0x10000;
  }
  if (in_stack_00000000 == 1) {
    if (extraout_r3 != 0) {
      uVar5 = 0;
      do {
        iVar2 = extraout_r2 + uVar5;
        uVar5 = uVar5 + uVar4;
        __raw_writesb((&DAT_000126cc)[ce_index],iVar2,uVar4);
      } while (uVar5 < extraout_r3);
    }
  }
  else if (extraout_r3 != 0) {
    uVar5 = 0;
    do {
      iVar2 = extraout_r2 + uVar5;
      iVar3 = (&DAT_000126cc)[ce_index] + uVar5;
      uVar5 = uVar5 + uVar4;
      mmiocpy(iVar2,iVar3);
    } while (uVar5 < extraout_r3);
  }
  DataSynchronizationBarrier(0xf);
  DataSynchronizationBarrier(0xe);
  *(uint *)(_LANCHOR1 + ce_index * 4 + 0x10) = *(uint *)(_LANCHOR1 + ce_index * 4 + 0x10) | 7;
  reset_flash();
  return 0;
}

