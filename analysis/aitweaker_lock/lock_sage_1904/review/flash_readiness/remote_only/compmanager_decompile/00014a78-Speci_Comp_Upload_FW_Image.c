
void * Speci_Comp_Upload_FW_Image
                 (void *param_1,undefined4 param_2,int param_3,size_t param_4,void *param_5,
                 undefined4 param_6)

{
  size_t sVar1;
  int iVar2;
  undefined4 uVar3;
  size_t sStack_20030;
  undefined4 uStack_2002c;
  undefined1 auStack_20028 [2];
  undefined1 uStack_20026;
  undefined4 uStack_20024;
  ushort uStack_20020;
  undefined1 auStack_2001e [4];
  undefined1 uStack_2001a;
  undefined1 auStack_20019 [4];
  undefined1 auStack_20015 [65529];
  undefined1 auStack_1001c [4];
  undefined4 uStack_10018;
  
  sStack_20030 = param_4;
  uStack_2002c = param_2;
  memset(auStack_20028,0,DAT_00014bac);
  memset(auStack_1001c,0,DAT_00014bac);
  uStack_20024 = param_6;
  uStack_20026 = (undefined1)param_3;
  memcpy(auStack_2001e,&uStack_2002c,4);
  uStack_2001a = 2;
  memcpy(auStack_20019,&sStack_20030,4);
  sVar1 = sStack_20030;
  memcpy(auStack_20015,param_5,sStack_20030);
  if (param_3 == 0xb) {
    uVar3 = 600;
  }
  else {
    uVar3 = 0x3c;
  }
  uStack_20020 = (short)sVar1 + 9U & 0xff;
  iVar2 = send_compmngr_command(auStack_20028,auStack_1001c,uVar3);
  if (iVar2 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00014bb0);
    uStack_10018 = DAT_00014bb4;
    memcpy(param_1,auStack_1001c,DAT_00014bac);
    return param_1;
  }
  memcpy(param_1,auStack_1001c,DAT_00014bac);
  return param_1;
}

