
undefined4 host_spi_flash_write(void)

{
  int iVar1;
  uint uVar2;
  uint extraout_r2;
  int extraout_r3;
  uint uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  bool bVar6;
  uint in_stack_00000000;
  int *in_stack_00000004;
  int in_stack_00000008;
  
  iVar1 = __gnu_mcount_nc();
  if (in_stack_00000000 != 0) {
    uVar3 = *(uint *)(iVar1 + 0x14);
    uVar2 = extraout_r3 + (uint)CARRY4(extraout_r2,in_stack_00000000);
    bVar6 = uVar3 <= uVar2;
    if (uVar2 == uVar3) {
      bVar6 = *(uint *)(iVar1 + 0x10) <= extraout_r2 + in_stack_00000000;
    }
    if (bVar6 && (uVar2 != uVar3 || extraout_r2 + in_stack_00000000 != *(uint *)(iVar1 + 0x10))) {
      return 0xffffffea;
    }
    uVar4 = *(undefined4 *)(iVar1 + 0xf4);
    if (in_stack_00000004 != (int *)0x0) {
      *in_stack_00000004 = 0;
    }
    down(host_spi_flash_lock);
    if (DAT_000126c8 == 0) {
      uVar5 = 2;
    }
    else if (_LANCHOR2 == 0x1940ef || _LANCHOR2 == 0x19ba20) {
      uVar5 = 2;
      enter_4byte_addr_mode(uVar4);
    }
    else {
      uVar5 = 0x12;
    }
    uVar2 = extraout_r3 >> 0x1f;
    iVar1 = (uVar2 ^ (extraout_r2 ^ uVar2) - uVar2 & 0xff) - uVar2;
    if (in_stack_00000000 + iVar1 < 0x101) {
      FUN_00010664(uVar4,in_stack_00000008,extraout_r2,in_stack_00000000,uVar5);
      *in_stack_00000004 = *in_stack_00000004 + in_stack_00000000;
    }
    else {
      uVar2 = 0x100 - iVar1;
      FUN_00010664(uVar4,in_stack_00000008,extraout_r2,uVar2,uVar5);
      *in_stack_00000004 = *in_stack_00000004 + uVar2;
      for (; uVar2 < in_stack_00000000; uVar2 = uVar2 + uVar3) {
        uVar3 = in_stack_00000000 - uVar2;
        if (0xff < uVar3) {
          uVar3 = 0x100;
        }
        FUN_00010664(uVar4,in_stack_00000008 + uVar2,uVar2 + extraout_r2,uVar3,uVar5);
        *in_stack_00000004 = *in_stack_00000004 + uVar3;
      }
    }
    up(DAT_00010d38);
  }
  return 0;
}

