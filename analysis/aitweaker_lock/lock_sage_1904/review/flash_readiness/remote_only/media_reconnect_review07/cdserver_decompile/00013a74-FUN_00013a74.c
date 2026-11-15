
undefined4 FUN_00013a74(undefined4 param_1,undefined4 param_2,undefined1 param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_58;
  undefined4 uStack_54;
  undefined4 local_4c;
  undefined1 local_41;
  undefined1 local_2f;
  
  memset(&local_58,0,0x3e);
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00013b40,DAT_00013b3c,DAT_00013b38);
  local_58 = *DAT_00013b44;
  uStack_54 = DAT_00013b44[1];
  local_41 = (undefined1)param_2;
  local_4c = 0x1e;
  local_2f = param_3;
  iVar1 = sigwrap_send(param_1,&local_58,0x3e,0);
  if (iVar1 < 1) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00013b4c,DAT_00013b3c,DAT_00013b48);
    iVar1 = FUN_000133cc(param_2);
    if (iVar1 == 0) {
      uVar2 = 1;
    }
    else {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00013b54,DAT_00013b3c,DAT_00013b50);
      uVar2 = 1;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}

