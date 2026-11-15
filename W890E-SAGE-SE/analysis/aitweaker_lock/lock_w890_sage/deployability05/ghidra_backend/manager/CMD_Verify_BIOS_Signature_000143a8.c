
void * CMD_Verify_BIOS_Signature(void *param_1)

{
  int iVar1;
  void *pvVar2;
  uint uVar3;
  undefined2 uStack_20034;
  undefined1 uStack_20032;
  undefined1 auStack_10028 [4];
  undefined4 uStack_10024;
  
  uVar3 = **(uint **)(DAT_0001449c + 0x143c0 + DAT_000144a0);
  memset(&uStack_20034,0,DAT_000144a4);
  memset(auStack_10028,0,DAT_000144a4);
  uStack_20034 = 0xb;
  uStack_20032 = 2;
  iVar1 = send_compmngr_command(&uStack_20034,auStack_10028,0x3c);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000144a8 + 0x14444);
    uStack_10024 = 0xffff;
  }
  pvVar2 = memcpy(param_1,auStack_10028,DAT_000144a4);
  uVar3 = uVar3 ^ **(uint **)(DAT_000144ac + 0x14470 + DAT_000144a0);
  if (uVar3 != 0) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(pvVar2,uVar3,0);
  }
  return param_1;
}

