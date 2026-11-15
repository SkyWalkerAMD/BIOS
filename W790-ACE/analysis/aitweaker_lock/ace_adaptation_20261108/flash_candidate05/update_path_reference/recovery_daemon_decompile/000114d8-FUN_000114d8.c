
undefined4 FUN_000114d8(char *param_1)

{
  int iVar1;
  int *piVar2;
  undefined4 uVar3;
  
  iVar1 = mkfifo(param_1,DAT_00011534);
  if ((iVar1 == -1) && (piVar2 = __errno_location(), *piVar2 != 0x11)) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_0001153c,DAT_00011538,0x43,param_1);
    uVar3 = 0xffffffff;
  }
  else {
    uVar3 = 0;
  }
  return uVar3;
}

