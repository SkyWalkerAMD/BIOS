
void * CMD_Get_BIOS_Version(void *param_1,undefined4 param_2,undefined1 param_3,undefined4 param_4)

{
  int iVar1;
  undefined4 uStack_2002c;
  undefined2 uStack_20028;
  undefined1 uStack_20026;
  undefined4 uStack_20024;
  undefined2 uStack_20020;
  undefined1 auStack_2001e [65538];
  undefined1 auStack_1001c [4];
  undefined4 uStack_10018;
  
  uStack_2002c = param_2;
  memset(&uStack_20028,0,DAT_00013668);
  memset(auStack_1001c,0,DAT_00013668);
  uStack_20028 = 10;
  uStack_20020 = 4;
  uStack_20026 = param_3;
  uStack_20024 = param_4;
  memcpy(auStack_2001e,&uStack_2002c,4);
  iVar1 = send_compmngr_command(&uStack_20028,auStack_1001c,0x3c);
  if (iVar1 == 0) {
    memcpy(param_1,auStack_1001c,DAT_00013668);
    return param_1;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_0001366c);
  uStack_10018 = DAT_00013670;
  memcpy(param_1,auStack_1001c,DAT_00013668);
  return param_1;
}

