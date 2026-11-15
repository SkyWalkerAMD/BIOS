
undefined4
bios_get_version(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  int iStack_1003c;
  int iStack_10038;
  undefined2 auStack_10034 [2];
  undefined4 uStack_10030;
  short sStack_1002c;
  undefined1 auStack_1002a [203];
  undefined1 auStack_ff5f [65339];
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  iStack_1003c = 0;
  uStack_8 = param_3;
  uStack_4 = param_4;
  IDBG_LINUXAPP_DbgOut(0x86,DAT_0001316c,DAT_00013168);
  ClearASUSBiosHeader();
  memset(auStack_10034,0,DAT_00013170);
  memcpy(&iStack_10038,(void *)((int)&uStack_8 + 2),4);
  if (iStack_10038 != *DAT_00013174) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00013178);
    sStack_1002c = 0;
    uStack_10030 = 6;
    goto LAB_00012f6c;
  }
  iVar1 = get_bios_file_size(&iStack_1003c);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_0001319c);
    sStack_1002c = 0;
    uStack_10030 = 0xff;
    goto LAB_00012f6c;
  }
  iVar1 = dlopen(DAT_0001317c,1);
  if ((iVar1 == 0) || (pcVar2 = (code *)dlsym(iVar1,DAT_00013180), pcVar2 == (code *)0x0)) {
LAB_00013098:
    dlclose(iVar1);
  }
  else {
    iVar3 = sigwrap_open(DAT_00013184,2);
    if (iVar3 < 0) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_000131ac);
    }
    else {
      if (iStack_1003c == 0x4000000) {
        puts(DAT_000131a8);
        iVar4 = (*pcVar2)(iVar3,iStack_1003c + -0x3000000,DAT_00013188,0x3000000);
      }
      else {
        iVar4 = (*pcVar2)(iVar3,iStack_1003c,DAT_00013188,0);
      }
      if (iVar4 != 0) {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_000131a4);
        uStack_10030 = 0xf1;
        sStack_1002c = 0;
        close(iVar3);
        dlclose(iVar1);
        goto LAB_00012f6c;
      }
      puts(DAT_0001318c);
      PrintBiosHeader(DAT_00013188);
      sigwrap_close(iVar3);
      iVar3 = sigwrap_open(DAT_00013190,2);
      if (iVar3 != -1) {
        iVar4 = (*pcVar2)(iVar3,0x1000000,DAT_00013194,0x3000000);
        if (iVar4 != 0) {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_000131a0);
          uStack_10030 = 0xf0;
        }
        puts(DAT_00013198);
        PrintBiosHeader(DAT_00013194);
        memcpy(auStack_1002a,DAT_00013194,0xcb);
        memcpy(auStack_ff5f,DAT_00013188,0xcb);
        sStack_1002c = sStack_1002c + 0x196;
        sigwrap_close(iVar3);
        goto LAB_00013098;
      }
      IDBG_LINUXAPP_DbgOut(0x86,DAT_000131b0,DAT_00013190);
    }
    sStack_1002c = 0;
    uStack_10030 = 0xff;
    dlclose(iVar1);
  }
LAB_00012f6c:
  auStack_10034[0] = param_1;
  send_compmngr_response(auStack_10034);
  return 0;
}

