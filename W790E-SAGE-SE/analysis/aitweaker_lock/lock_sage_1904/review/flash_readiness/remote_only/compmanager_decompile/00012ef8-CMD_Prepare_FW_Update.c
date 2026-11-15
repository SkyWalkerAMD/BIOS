
void * CMD_Prepare_FW_Update
                 (void *param_1,undefined4 param_2,int param_3,undefined4 param_4,undefined1 param_5
                 ,undefined1 param_6,undefined4 param_7)

{
  int iVar1;
  undefined4 uStack_20038;
  undefined4 uStack_20034;
  undefined2 uStack_20030;
  undefined1 uStack_2002e;
  undefined4 uStack_2002c;
  undefined2 uStack_20028;
  undefined1 auStack_20026 [4];
  undefined1 auStack_20022 [4];
  undefined1 uStack_2001e;
  undefined1 uStack_2001d;
  undefined1 auStack_10024 [4];
  undefined4 uStack_10020;
  
  uStack_20038 = param_4;
  uStack_20034 = param_2;
  memset(&uStack_20030,0,DAT_00013058);
  memset(auStack_10024,0,DAT_00013058);
  uStack_20030 = 1;
  uStack_20028 = 8;
  uStack_2002e = (undefined1)param_3;
  uStack_2002c = param_7;
  memcpy(auStack_20026,&uStack_20034,4);
  memcpy(auStack_20022,&uStack_20038,4);
  if (param_3 == 1) {
    uStack_20028 = 9;
    uStack_2001e = param_6;
    uStack_2001d = param_5;
  }
  else if (param_3 == 0x10) {
    uStack_2001e = param_6;
  }
  iVar1 = send_compmngr_command(&uStack_20030,auStack_10024);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_0001305c);
    uStack_10020 = DAT_00013060;
    memcpy(param_1,auStack_10024,DAT_00013058);
    return param_1;
  }
  memcpy(param_1,auStack_10024,DAT_00013058);
  return param_1;
}

