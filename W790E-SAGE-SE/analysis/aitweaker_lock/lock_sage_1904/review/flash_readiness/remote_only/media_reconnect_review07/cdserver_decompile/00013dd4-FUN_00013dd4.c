
void FUN_00013dd4(void)

{
  int iVar1;
  
  iVar1 = set_active_session(2,0);
  if (iVar1 == 0) {
    return;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00013e08,DAT_00013e04,0x97);
  return;
}

