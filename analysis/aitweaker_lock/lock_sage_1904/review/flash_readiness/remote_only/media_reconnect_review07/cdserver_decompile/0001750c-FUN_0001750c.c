
undefined4 FUN_0001750c(void)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = safe_system(DAT_0001754c);
  if (-1 < iVar1) {
    uVar2 = FUN_00018360(DAT_00017554,DAT_00017550);
    return uVar2;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00017560,DAT_0001755c,DAT_00017558);
  return 0xffffffff;
}

