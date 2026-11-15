
undefined4 FUN_00018620(undefined4 param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  uVar3 = DAT_000186a4;
  iVar1 = sigwrap_open(DAT_000186a4,2);
  if (iVar1 < 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000186b0,DAT_000186ac,DAT_000186a8,uVar3);
    sigwrap_close(iVar1);
    uVar3 = 0xffffffff;
  }
  else {
    iVar2 = sigwrap_write(iVar1,param_1,param_2);
    if (iVar2 == param_2) {
      sigwrap_close(iVar1);
      uVar3 = 0;
    }
    else {
      sigwrap_close(iVar1);
      uVar3 = 0xffffffff;
    }
  }
  return uVar3;
}

