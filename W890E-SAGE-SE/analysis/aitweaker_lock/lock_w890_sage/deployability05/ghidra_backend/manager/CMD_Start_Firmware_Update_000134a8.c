
void * CMD_Start_Firmware_Update
                 (void *param_1,undefined4 param_2,int param_3,undefined4 param_4,undefined4 param_5
                 ,undefined4 param_6,undefined4 param_7)

{
  void *pvVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined1 auStack_30050 [65556];
  undefined2 uStack_2003c;
  undefined1 uStack_2003a;
  undefined4 uStack_20038;
  undefined2 uStack_20034;
  undefined4 uStack_20032;
  undefined4 uStack_2002e;
  undefined4 uStack_2002a;
  undefined4 uStack_20026;
  undefined1 auStack_10030 [4];
  int iStack_1002c;
  
  uVar3 = **(uint **)(DAT_0001361c + 0x134c4 + DAT_00013620);
  memset(&uStack_2003c,0,DAT_00013624);
  pvVar1 = memset(auStack_10030,0,DAT_00013624);
  uStack_2003c = 3;
  uStack_2003a = (undefined1)param_3;
  uStack_20038 = param_7;
  uStack_20034 = 0xc;
  uStack_2002a = param_5;
  uStack_20026 = param_6;
  if (param_3 == 0xb) {
    uVar4 = 600;
  }
  else {
    uVar4 = 0x3c;
  }
  uStack_20032 = param_2;
  uStack_2002e = param_4;
  iVar2 = send_compmngr_command(&uStack_2003c,pvVar1,uVar4);
  if ((iVar2 != 0) || ((param_3 == 0xb && (iStack_1002c != 0)))) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00013628 + 0x135b0);
    if (param_3 == 0xb) {
      CMD_Exit_FW_Update_mode(auStack_30050,param_2);
    }
    iStack_1002c = 0xffff;
  }
  pvVar1 = memcpy(param_1,auStack_10030,DAT_00013624);
  uVar3 = uVar3 ^ **(uint **)(DAT_0001362c + 0x135f0 + DAT_00013620);
  if (uVar3 == 0) {
    return param_1;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(pvVar1,uVar3,0);
}

