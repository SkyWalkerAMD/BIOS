
void * Speci_Comp_Prepare_FW_Update
                 (void *param_1,undefined4 param_2,int param_3,undefined4 param_4,undefined4 param_5
                 ,undefined4 param_6)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uStack_20030;
  undefined4 uStack_2002c;
  undefined1 auStack_20028 [2];
  undefined1 uStack_20026;
  undefined4 uStack_20024;
  undefined2 uStack_20020;
  undefined1 auStack_2001e [4];
  undefined1 uStack_2001a;
  undefined1 auStack_20019 [4];
  undefined1 auStack_20015 [65529];
  undefined1 auStack_1001c [4];
  undefined4 uStack_10018;
  
  uVar2 = param_6;
  uStack_20030 = param_4;
  uStack_2002c = param_2;
  memset(auStack_20028,0,DAT_000143d0);
  memset(auStack_1001c,0,DAT_000143d0);
  uStack_20024 = uVar2;
  uStack_20026 = (undefined1)param_3;
  memcpy(auStack_2001e,&uStack_2002c,4);
  uStack_2001a = 1;
  memcpy(auStack_20019,&uStack_20030,4);
  memcpy(auStack_20015,&param_5,4);
  if (param_3 == 0xb) {
    uVar2 = 600;
  }
  else {
    uVar2 = 0x3c;
  }
  uStack_20020 = 0xd;
  iVar1 = send_compmngr_command(auStack_20028,auStack_1001c,uVar2);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000143d4);
    uStack_10018 = DAT_000143d8;
    memcpy(param_1,auStack_1001c,DAT_000143d0);
    return param_1;
  }
  memcpy(param_1,auStack_1001c,DAT_000143d0);
  return param_1;
}

