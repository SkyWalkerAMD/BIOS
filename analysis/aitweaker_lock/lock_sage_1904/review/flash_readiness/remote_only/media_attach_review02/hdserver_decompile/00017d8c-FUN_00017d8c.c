
undefined4 FUN_00017d8c(void)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = safe_system(DAT_00017dcc);
  if (-1 < iVar1) {
    uVar2 = FUN_00018b0c(DAT_00017dd4,DAT_00017dd0);
    return uVar2;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00017ddc,DAT_00017dd8,0x21c);
  return 0xffffffff;
}

