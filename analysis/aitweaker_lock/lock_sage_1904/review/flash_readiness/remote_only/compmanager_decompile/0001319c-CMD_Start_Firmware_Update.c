
void * CMD_Start_Firmware_Update
                 (void *param_1,undefined4 param_2,int param_3,undefined4 param_4,undefined4 param_5
                 ,undefined4 param_6,undefined4 param_7)

{
  undefined4 uVar1;
  int iVar2;
  undefined1 auStack_30048 [65552];
  undefined4 uStack_20038;
  undefined4 uStack_20034;
  undefined2 uStack_20030;
  undefined1 uStack_2002e;
  undefined4 uStack_2002c;
  undefined2 uStack_20028;
  undefined1 auStack_20026 [4];
  undefined1 auStack_20022 [4];
  undefined1 auStack_2001e [4];
  undefined1 auStack_2001a [65526];
  undefined1 auStack_10024 [4];
  int iStack_10020;
  
  uVar1 = param_7;
  uStack_20038 = param_4;
  uStack_20034 = param_2;
  memset(&uStack_20030,0,DAT_00013330);
  memset(auStack_10024,0,DAT_00013330);
  uStack_20030 = 3;
  uStack_20028 = 0xc;
  uStack_2002e = (undefined1)param_3;
  uStack_2002c = uVar1;
  memcpy(auStack_20026,&uStack_20034,4);
  memcpy(auStack_20022,&uStack_20038,4);
  memcpy(auStack_2001e,&param_5,4);
  memcpy(auStack_2001a,&param_6,4);
  if (param_3 == 0xb) {
    iVar2 = send_compmngr_command(&uStack_20030,auStack_10024,600);
    if (iVar2 != 0 || iStack_10020 != 0) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00013334);
      CMD_Exit_FW_Update_mode(auStack_30048,uStack_20034);
      goto LAB_000132b0;
    }
  }
  else {
    iVar2 = send_compmngr_command(&uStack_20030,auStack_10024,0x3c);
    if (iVar2 != 0) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00013334);
LAB_000132b0:
      iStack_10020 = DAT_00013338;
      memcpy(param_1,auStack_10024,DAT_00013330);
      return param_1;
    }
  }
  memcpy(param_1,auStack_10024,DAT_00013330);
  return param_1;
}

