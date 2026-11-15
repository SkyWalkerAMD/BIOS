
undefined4 bios_activate_update(undefined2 param_1)

{
  int iVar1;
  undefined2 auStack_10024 [2];
  undefined4 uStack_10020;
  undefined2 uStack_1001c;
  
  memset(auStack_10024,0,DAT_0001225c);
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00012268,DAT_0001226c,DAT_00012264,DAT_00012260);
  iVar1 = RebootHost();
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00012270);
    uStack_10020 = 0xff;
  }
  uStack_1001c = 0;
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

