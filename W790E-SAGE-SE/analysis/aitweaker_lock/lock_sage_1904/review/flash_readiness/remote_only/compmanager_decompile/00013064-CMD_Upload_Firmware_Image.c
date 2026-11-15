
void * CMD_Upload_Firmware_Image
                 (void *param_1,undefined4 param_2,int param_3,size_t param_4,void *param_5,
                 undefined4 param_6)

{
  size_t __n;
  int iVar1;
  undefined4 uVar2;
  size_t sStack_20038;
  undefined4 uStack_20034;
  undefined2 uStack_20030;
  undefined1 uStack_2002e;
  undefined4 uStack_2002c;
  short sStack_20028;
  undefined1 auStack_20026 [4];
  undefined1 auStack_20022 [4];
  undefined1 auStack_2001e [65530];
  undefined1 auStack_10024 [4];
  undefined4 uStack_10020;
  
  sStack_20038 = param_4;
  uStack_20034 = param_2;
  memset(&uStack_20030,0,DAT_00013190);
  memset(auStack_10024,0,DAT_00013190);
  __n = sStack_20038;
  sStack_20028 = (short)sStack_20038 + 8;
  uStack_20030 = 2;
  uStack_2002e = (undefined1)param_3;
  uStack_2002c = param_6;
  memcpy(auStack_20026,&uStack_20034,4);
  memcpy(auStack_20022,&sStack_20038,4);
  memcpy(auStack_2001e,param_5,__n);
  if (param_3 == 0xb) {
    uVar2 = 600;
  }
  else {
    uVar2 = 0x3c;
  }
  iVar1 = send_compmngr_command(&uStack_20030,auStack_10024,uVar2);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00013194);
    uStack_10020 = DAT_00013198;
    memcpy(param_1,auStack_10024,DAT_00013190);
    return param_1;
  }
  memcpy(param_1,auStack_10024,DAT_00013190);
  return param_1;
}

