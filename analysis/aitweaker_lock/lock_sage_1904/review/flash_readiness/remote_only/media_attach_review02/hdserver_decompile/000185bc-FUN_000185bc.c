
int FUN_000185bc(uint param_1)

{
  int iVar1;
  undefined1 auStack_20 [4];
  undefined1 local_1c;
  
  if (param_1 < 4) {
    local_1c = (undefined1)param_1;
    iVar1 = ioctl(*DAT_00018610,DAT_00018614,auStack_20);
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_0001861c,DAT_00018618,0xd5,param_1);
    iVar1 = -1;
  }
  return iVar1;
}

