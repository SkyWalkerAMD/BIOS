
undefined4 bios_backup_image(undefined2 param_1)

{
  int iVar1;
  char acStack_100ac [64];
  char acStack_1006c [64];
  undefined2 auStack_1002c [2];
  undefined4 uStack_10028;
  undefined2 uStack_10024;
  
  memset(acStack_100ac,0,0x40);
  iVar1 = DAT_000123c0;
  memset(acStack_1006c,0,0x40);
  memset(auStack_1002c,0,DAT_000123c4);
  snprintf(acStack_100ac,0x40,DAT_000123c8,*(undefined4 *)(iVar1 + 0x160));
  snprintf(acStack_1006c,0x40,DAT_000123cc,*(undefined4 *)(iVar1 + 0x160));
  iVar1 = rename(acStack_100ac,acStack_1006c);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000123d0);
    uStack_10028 = 0xff;
  }
  uStack_10024 = 0;
  auStack_1002c[0] = param_1;
  send_compmngr_response(auStack_1002c);
  return 0;
}

