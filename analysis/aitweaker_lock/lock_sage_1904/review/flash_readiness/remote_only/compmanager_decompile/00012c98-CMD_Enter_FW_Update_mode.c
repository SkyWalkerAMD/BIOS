
void * CMD_Enter_FW_Update_mode(void *param_1)

{
  undefined4 uVar1;
  int iVar2;
  FILE *__stream;
  undefined4 uStack_2002c;
  undefined1 auStack_20028 [65548];
  undefined1 auStack_1001c [4];
  int iStack_10018;
  undefined1 auStack_10012 [65538];
  
  uStack_2002c = 0;
  memset(auStack_20028,0,DAT_00012dcc);
  memset(auStack_1001c,0,DAT_00012dcc);
  iVar2 = send_compmngr_command(auStack_20028,auStack_1001c,0x3c);
  if (iVar2 == 0) {
    if (iStack_10018 == 0) {
      touch(DAT_00012de0);
    }
    memcpy(&uStack_2002c,auStack_10012,4);
    uVar1 = uStack_2002c;
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00012dd0,uStack_2002c);
    __stream = fopen(DAT_00012dd8,DAT_00012dd4);
    fprintf(__stream,DAT_00012ddc,uVar1);
    fclose(__stream);
    memcpy(param_1,auStack_1001c,DAT_00012dcc);
    return param_1;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00012de4);
  iStack_10018 = DAT_00012de8;
  memcpy(param_1,auStack_1001c,DAT_00012dcc);
  return param_1;
}

