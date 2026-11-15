
undefined4
bios_get_version(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  undefined4 uStack_10040;
  undefined4 uStack_1003c;
  int iStack_10038;
  undefined2 auStack_10034 [2];
  undefined4 uStack_10030;
  short sStack_1002c;
  undefined1 auStack_1002a [203];
  undefined1 auStack_ff5f [65335];
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  uStack_10040 = 0;
  uStack_1003c = 0;
  uStack_8 = param_3;
  uStack_4 = param_4;
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00013be8,DAT_00013be4);
  ClearASUSBiosHeader();
  memset(auStack_10034,0,DAT_00013bec);
  memcpy(&iStack_10038,(void *)((int)&uStack_8 + 2),4);
  if (iStack_10038 == *DAT_00013bf0) {
    iVar1 = get_bios_file_size(&uStack_10040);
    if (iVar1 == 0) {
      iVar1 = dlopen(DAT_00013bf8,1);
      if ((iVar1 != 0) && (pcVar2 = (code *)dlsym(iVar1,DAT_00013bfc), pcVar2 != (code *)0x0)) {
        iVar3 = sigwrap_open(DAT_00013c00,2);
        if (iVar3 < 0) {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_00013c28);
          sStack_1002c = 0;
          uStack_10030 = 0xff;
          dlclose(iVar1);
          goto LAB_000139f0;
        }
        iVar4 = (*pcVar2)(iVar3,uStack_10040,DAT_00013c04,0);
        if (iVar4 != 0) {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_00013c24);
          sStack_1002c = 0;
          uStack_10030 = 0xf1;
          close(iVar3);
          dlclose(iVar1);
          goto LAB_000139f0;
        }
        puts(DAT_00013c08);
        PrintBiosHeader(DAT_00013c04);
        sigwrap_close(iVar3);
        iVar3 = sigwrap_open(DAT_00013c0c,2);
        if (iVar3 == -1) {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_00013c2c,DAT_00013c0c);
          sStack_1002c = 0;
          uStack_10030 = 0xff;
          dlclose(iVar1);
          goto LAB_000139f0;
        }
        get_bios_mtd_size(iVar3,&uStack_1003c);
        printf(DAT_00013c10,DAT_00013c0c,uStack_1003c);
        iVar4 = (*pcVar2)(iVar3,uStack_1003c,DAT_00013c14,0);
        if (iVar4 != 0) {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_00013c20);
          uStack_10030 = 0xf0;
        }
        puts(DAT_00013c18);
        PrintBiosHeader(DAT_00013c14);
        memcpy(auStack_1002a,DAT_00013c14,0xcb);
        memcpy(auStack_ff5f,DAT_00013c04,0xcb);
        sStack_1002c = sStack_1002c + 0x196;
        sigwrap_close(iVar3);
      }
      dlclose(iVar1);
    }
    else {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00013c1c);
      sStack_1002c = 0;
      uStack_10030 = 0xff;
    }
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00013bf4);
    sStack_1002c = 0;
    uStack_10030 = 6;
  }
LAB_000139f0:
  auStack_10034[0] = param_1;
  send_compmngr_response(auStack_10034);
  return 0;
}

