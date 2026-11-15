
void * CMD_BIOS_Exit_Firmware_Update(void *param_1)

{
  int iVar1;
  undefined2 uStack_20020;
  undefined1 uStack_2001e;
  undefined2 uStack_20018;
  undefined1 auStack_10014 [4];
  undefined4 uStack_10010;
  
  uStack_20020 = 0xe;
  uStack_2001e = 2;
  uStack_20018 = 0;
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00013a5c,DAT_00013a58,DAT_00013a54,DAT_00013a50);
  iVar1 = send_compmngr_command(&uStack_20020,auStack_10014,0x3c);
  if (iVar1 == 0) {
    memcpy(param_1,auStack_10014,DAT_00013a60);
    return param_1;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00013a64);
  uStack_10010 = DAT_00013a68;
  memcpy(param_1,auStack_10014,DAT_00013a60);
  return param_1;
}

