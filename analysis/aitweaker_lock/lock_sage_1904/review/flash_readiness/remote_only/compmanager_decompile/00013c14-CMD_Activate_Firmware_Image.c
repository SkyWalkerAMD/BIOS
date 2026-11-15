
void * CMD_Activate_Firmware_Image(void *param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined2 uStack_20028;
  undefined1 uStack_20026;
  undefined4 uStack_20024;
  undefined1 auStack_1001c [4];
  undefined4 uStack_10018;
  
  memset(&uStack_20028,0,DAT_00013ce8);
  memset(auStack_1001c,0,DAT_00013ce8);
  if (param_2 == 0xb) {
    uVar2 = 600;
  }
  else {
    uVar2 = 0x3c;
  }
  uStack_20026 = (undefined1)param_2;
  uStack_20028 = 5;
  uStack_20024 = param_3;
  iVar1 = send_compmngr_command(&uStack_20028,auStack_1001c,uVar2);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00013cec);
    uStack_10018 = DAT_00013cf0;
    memcpy(param_1,auStack_1001c,DAT_00013ce8);
    return param_1;
  }
  memcpy(param_1,auStack_1001c,DAT_00013ce8);
  return param_1;
}

