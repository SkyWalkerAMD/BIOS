
undefined4 FUN_00011878(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  short sVar1;
  undefined2 auStack_10024 [2];
  undefined4 uStack_10020;
  short sStack_1001c;
  undefined2 local_10;
  undefined1 local_e;
  undefined4 local_8;
  undefined4 uStack_4;
  
  local_8 = param_3;
  uStack_4 = param_4;
  memset(auStack_10024,0,DAT_00011924);
  sVar1 = (short)local_8;
  if ((short)local_8 == 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00011928);
    sStack_1001c = sVar1;
    uStack_10020 = 1;
  }
  else {
    local_e = (undefined1)((uint)param_1 >> 0x10);
    Add_CompBook_Event_Record(local_e,(int)&local_8 + 2);
    sStack_1001c = 0;
  }
  local_10 = (undefined2)param_1;
  auStack_10024[0] = local_10;
  send_compmngr_response(auStack_10024);
  return 0;
}

