
void * CMD_Verify_BIOS_Signature(void *param_1)

{
  int iVar1;
  undefined2 uStack_20020;
  undefined1 uStack_2001e;
  undefined1 auStack_10014 [4];
  undefined4 uStack_10010;
  
  memset(&uStack_20020,0,DAT_00013db8);
  memset(auStack_10014,0,DAT_00013db8);
  uStack_20020 = 0xb;
  uStack_2001e = 2;
  iVar1 = send_compmngr_command(&uStack_20020,auStack_10014,0x3c);
  if (iVar1 == 0) {
    memcpy(param_1,auStack_10014,DAT_00013db8);
    return param_1;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00013dbc);
  uStack_10010 = DAT_00013dc0;
  memcpy(param_1,auStack_10014,DAT_00013db8);
  return param_1;
}

