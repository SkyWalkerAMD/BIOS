
undefined4 FUN_00011aa8(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  char *__name;
  int iVar1;
  int iStack_10030;
  undefined2 auStack_1002c [2];
  undefined4 uStack_10028;
  undefined2 uStack_10024;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  __name = DAT_00011bac;
  iStack_10030 = 0;
  uStack_8 = param_3;
  uStack_4 = param_4;
  memset(auStack_1002c,0,DAT_00011bb0);
  iVar1 = access(__name,0);
  if (iVar1 == 0) {
    memcpy(&iStack_10030,(void *)((int)&uStack_8 + 2),4);
    if (iStack_10030 == *DAT_00011bb8) {
      iVar1 = unlink(__name);
      if (iVar1 == -1) {
        IDBG_LINUXAPP_DbgOut(0x84,DAT_00011bc8,DAT_00011bc4,DAT_00011bc0,__name);
      }
    }
    else {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00011bbc);
      uStack_10028 = 6;
    }
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00011bb4);
    uStack_10028 = 0xffffffff;
  }
  uStack_10024 = 0;
  auStack_1002c[0] = param_1;
  send_compmngr_response(auStack_1002c);
  return 0;
}

