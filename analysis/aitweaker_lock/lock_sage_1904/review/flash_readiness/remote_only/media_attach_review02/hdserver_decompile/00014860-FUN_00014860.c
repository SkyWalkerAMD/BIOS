
void FUN_00014860(void)

{
  int iVar1;
  
  iVar1 = set_active_session(4,0);
  if (iVar1 == 0) {
    return;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00014894,DAT_00014890,0x96);
  return;
}

