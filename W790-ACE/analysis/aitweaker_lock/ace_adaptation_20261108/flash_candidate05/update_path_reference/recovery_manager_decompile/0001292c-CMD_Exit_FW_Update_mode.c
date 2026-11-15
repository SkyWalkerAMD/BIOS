
void * CMD_Exit_FW_Update_mode(void *param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uStack_20024;
  undefined2 auStack_20020 [4];
  undefined2 uStack_20018;
  undefined1 auStack_20016 [65538];
  undefined1 auStack_10014 [4];
  int iStack_10010;
  
  uStack_20024 = param_2;
  memset(auStack_20020,0,DAT_00012a28);
  memset(auStack_10014,0,DAT_00012a28);
  auStack_20020[0] = 2;
  uStack_20018 = 4;
  memcpy(auStack_20016,&uStack_20024,4);
  iVar1 = send_compmngr_command(auStack_20020,auStack_10014,0x3c);
  if (iVar1 == 0) {
    if (iStack_10010 == 0) {
      unlink(DAT_00012a2c);
    }
    memcpy(param_1,auStack_10014,DAT_00012a28);
    return param_1;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00012a30);
  iStack_10010 = DAT_00012a34;
  memcpy(param_1,auStack_10014,DAT_00012a28);
  return param_1;
}

