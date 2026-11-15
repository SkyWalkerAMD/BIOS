
void * Speci_Comp_Get_Update_Progress
                 (void *param_1,undefined4 param_2,int param_3,undefined1 param_4,void *param_5,
                 undefined4 param_6)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uStack_20034;
  undefined1 auStack_20030 [2];
  undefined1 uStack_2002e;
  undefined4 uStack_2002c;
  undefined2 uStack_20028;
  undefined1 auStack_20026 [4];
  undefined1 uStack_20022;
  undefined1 uStack_20021;
  undefined1 auStack_10024 [4];
  undefined4 uStack_10020;
  ushort uStack_1001c;
  undefined1 auStack_1001a [65542];
  
  uStack_20034 = param_2;
  memset(auStack_20030,0,DAT_00014f94);
  memset(auStack_10024,0,DAT_00014f94);
  uStack_2002c = param_6;
  uStack_2002e = (undefined1)param_3;
  memcpy(auStack_20026,&uStack_20034,4);
  if (param_3 == 0xb) {
    uVar2 = 600;
  }
  else {
    uVar2 = 0x3c;
  }
  uStack_20022 = 6;
  uStack_20028 = 6;
  uStack_20021 = param_4;
  iVar1 = send_compmngr_command(auStack_20030,auStack_10024,uVar2);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00014f9c);
    uStack_10020 = DAT_00014fa0;
    memcpy(param_1,auStack_10024,DAT_00014f94);
    return param_1;
  }
  if (uStack_1001c < 5) {
    memcpy(param_5,auStack_1001a,(uint)uStack_1001c);
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00014f98);
  }
  memcpy(param_1,auStack_10024,DAT_00014f94);
  return param_1;
}

