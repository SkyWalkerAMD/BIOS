
undefined4 FUN_00018768(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  uVar3 = DAT_000187f0;
  iVar1 = sigwrap_open(DAT_000187f0,2);
  if (iVar1 < 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000187fc,DAT_000187f8,DAT_000187f4,uVar3);
    sigwrap_close(iVar1);
    uVar3 = 0xffffffff;
  }
  else if ((param_1 == 0) || (iVar2 = sigwrap_write(iVar1,param_1,8), iVar2 != 8)) {
    sigwrap_close(iVar1);
    uVar3 = 0xffffffff;
  }
  else {
    sigwrap_close(iVar1);
    uVar3 = 0;
  }
  return uVar3;
}

