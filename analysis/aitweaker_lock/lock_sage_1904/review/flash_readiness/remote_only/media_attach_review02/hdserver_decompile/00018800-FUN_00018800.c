
undefined4 FUN_00018800(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  uVar1 = DAT_000188a0;
  iVar2 = sigwrap_open(DAT_000188a0,2);
  if (iVar2 < 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000188b0,DAT_000188ac,DAT_000188a8,uVar1);
    sigwrap_close(iVar2);
  }
  else {
    if (param_1 != 0) {
      if (*DAT_000188a4 == '\x02') {
        iVar4 = 6;
      }
      else {
        iVar4 = 4;
      }
      iVar3 = sigwrap_write(iVar2,param_1);
      if (iVar3 == iVar4) {
        sigwrap_close(iVar2);
        return 0;
      }
    }
    sigwrap_close(iVar2);
  }
  return 0xffffffff;
}

