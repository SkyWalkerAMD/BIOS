
undefined4 FUN_00013960(undefined4 param_1,undefined4 param_2,undefined1 param_3)

{
  int iVar1;
  undefined4 local_58;
  undefined4 uStack_54;
  undefined4 local_4c;
  undefined1 local_41;
  undefined1 local_2f;
  
  memset(&local_58,0,0x3e);
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00013a3c,DAT_00013a38,0x2d8);
  local_58 = *DAT_00013a40;
  uStack_54 = DAT_00013a40[1];
  local_41 = (undefined1)param_2;
  local_4c = 0x1e;
  local_2f = param_3;
  iVar1 = sigwrap_send(param_1,&local_58,0x3e,0);
  if (0 < iVar1) {
    return 0;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00013a48,DAT_00013a38,DAT_00013a44);
  iVar1 = FUN_00013770(param_2);
  if (iVar1 == 0) {
    FUN_00012e68(param_2);
    return 1;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00013a50,DAT_00013a38,DAT_00013a4c);
  return 1;
}

