
void * CMD_Prepare_FW_Update
                 (void *param_1,undefined4 param_2,int param_3,undefined4 param_4,undefined1 param_5
                 ,undefined1 param_6,undefined4 param_7)

{
  int iVar1;
  void *pvVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined2 uStack_20044;
  undefined1 uStack_20042;
  undefined4 uStack_20040;
  undefined2 uStack_2003c;
  undefined4 uStack_2003a;
  undefined4 uStack_20036;
  undefined1 uStack_20032;
  undefined1 uStack_20031;
  undefined1 auStack_10038 [4];
  undefined4 uStack_10034;
  
  uVar3 = **(uint **)(DAT_00013338 + 0x131f0 + DAT_0001333c);
  memset(&uStack_20044,0,DAT_00013340);
  memset(auStack_10038,0,DAT_00013340);
  uStack_20044 = 1;
  uStack_20042 = (undefined1)param_3;
  uStack_20040 = param_7;
  uStack_2003c = 8;
  if (param_3 == 1) {
    uStack_20032 = param_6;
    uStack_2003c = 9;
    uVar4 = 0xb4;
    uStack_20031 = param_5;
  }
  else if (param_3 == 0x10) {
    uVar4 = 0x3c;
    uStack_20032 = param_6;
  }
  else if (param_3 == 0xb) {
    uVar4 = 600;
  }
  else {
    uVar4 = 0x3c;
  }
  uStack_2003a = param_2;
  uStack_20036 = param_4;
  iVar1 = send_compmngr_command(&uStack_20044,auStack_10038,uVar4);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00013344 + 0x132c0);
    uStack_10034 = 0xffff;
  }
  pvVar2 = memcpy(param_1,auStack_10038,DAT_00013340);
  uVar3 = uVar3 ^ **(uint **)(DAT_00013348 + 0x132ec + DAT_0001333c);
  if (uVar3 != 0) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(pvVar2,uVar3,0);
  }
  return param_1;
}

