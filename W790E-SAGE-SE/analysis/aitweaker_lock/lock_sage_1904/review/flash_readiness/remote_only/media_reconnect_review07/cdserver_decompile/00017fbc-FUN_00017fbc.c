
undefined4 FUN_00017fbc(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  uVar3 = DAT_00018044;
  iVar1 = sigwrap_open(DAT_00018044,2);
  if (iVar1 < 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00018050,DAT_0001804c,DAT_00018048,uVar3);
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

