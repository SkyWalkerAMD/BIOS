
undefined4 FUN_00011bf8(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  stat64 sStack_70;
  
  if (7 < param_1) {
    return 0;
  }
  iVar1 = __xstat64(3,*(char **)(DAT_00011c8c + param_1 * 4 + 0x20),&sStack_70);
  if (iVar1 == 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011c9c,DAT_00011c94,0xde,param_1);
    uVar2 = 0xffffffff;
  }
  else {
    if ((*DAT_00011c90 & 1) != 0) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00011c98,DAT_00011c94,0xda,param_1);
    }
    uVar2 = 0;
  }
  return uVar2;
}

