
undefined4 FUN_00011704(undefined2 param_1,undefined4 param_2,uint param_3)

{
  undefined1 auStack_10030 [12];
  undefined2 auStack_10024 [2];
  undefined4 uStack_10020;
  undefined2 uStack_1001c;
  undefined1 auStack_1001a [65542];
  undefined1 local_6;
  
  memset(auStack_10024,0,DAT_000117c0);
  if ((param_3 & 0xffff) == 1) {
    local_6 = (undefined1)(param_3 >> 0x10);
    Get_CompBook_ReposInfo(local_6,auStack_10030);
    uStack_1001c = 10;
    memcpy(auStack_1001a,auStack_10030,10);
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000117c4);
    uStack_1001c = 0;
    uStack_10020 = 0xff;
  }
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

