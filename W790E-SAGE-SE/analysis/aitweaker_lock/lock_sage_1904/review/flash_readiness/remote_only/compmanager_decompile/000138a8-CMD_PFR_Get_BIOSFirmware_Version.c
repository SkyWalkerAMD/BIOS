
void * CMD_PFR_Get_BIOSFirmware_Version(void *param_1,undefined1 param_2,undefined1 param_3)

{
  int iVar1;
  undefined2 uStack_20028;
  undefined1 uStack_20026;
  undefined2 uStack_20020;
  undefined1 uStack_2001e;
  undefined1 uStack_2001d;
  undefined1 auStack_1001c [4];
  undefined4 uStack_10018;
  
  memset(&uStack_20028,0,DAT_00013980);
  memset(auStack_1001c,0,DAT_00013980);
  uStack_20028 = 0xd;
  uStack_20026 = 2;
  uStack_20020 = 2;
  uStack_2001e = param_2;
  uStack_2001d = param_3;
  iVar1 = send_compmngr_command(&uStack_20028,auStack_1001c,0x3c);
  if (iVar1 == 0) {
    memcpy(param_1,auStack_1001c,DAT_00013980);
    return param_1;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00013984);
  uStack_10018 = DAT_00013988;
  memcpy(param_1,auStack_1001c,DAT_00013980);
  return param_1;
}

