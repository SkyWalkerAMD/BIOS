
int FUN_00017e10(uint param_1)

{
  int iVar1;
  undefined1 auStack_20 [4];
  undefined1 local_1c;
  
  if (param_1 < 4) {
    local_1c = (undefined1)param_1;
    iVar1 = ioctl(*DAT_00017e64,DAT_00017e68,auStack_20);
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00017e70,DAT_00017e6c,0xfa,param_1);
    iVar1 = -1;
  }
  return iVar1;
}

