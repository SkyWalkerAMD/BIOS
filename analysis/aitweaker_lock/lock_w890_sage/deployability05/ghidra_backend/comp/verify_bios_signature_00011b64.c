
undefined4 verify_bios_signature(undefined2 *param_1)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  undefined2 auStack_10028 [2];
  undefined4 uStack_10024;
  undefined2 uStack_10020;
  
  uVar5 = **(uint **)(DAT_00011c78 + 0x11b7c + DAT_00011c7c);
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00011c80 + 0x11bb4,DAT_00011c84 + 0x11bb8);
  memset(auStack_10028,0,DAT_00011c88);
  iVar1 = dlopen(DAT_00011c8c + 0x11bd8,1);
  if (((iVar1 != 0) && (pcVar2 = (code *)dlsym(iVar1,DAT_00011c90 + 0x11bec), pcVar2 != (code *)0x0)
      ) && (iVar3 = (*pcVar2)(), iVar3 != 0)) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00011c94 + 0x11c10);
    uStack_10024 = 0xff;
    uStack_10020 = 0;
  }
  dlclose(iVar1);
  auStack_10028[0] = *param_1;
  uVar4 = send_compmngr_response(auStack_10028);
  uVar5 = uVar5 ^ **(uint **)(DAT_00011c98 + 0x11c4c + DAT_00011c7c);
  if (uVar5 != 0) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(uVar4,uVar5,0);
  }
  return 0;
}

