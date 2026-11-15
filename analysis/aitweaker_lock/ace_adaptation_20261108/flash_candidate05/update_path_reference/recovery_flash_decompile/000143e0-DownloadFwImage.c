
undefined4 DownloadFwImage(undefined4 param_1)

{
  int iVar1;
  undefined4 local_a78 [63];
  undefined4 local_97c;
  undefined4 local_978;
  undefined4 uStack_974;
  undefined4 uStack_970;
  undefined1 auStack_96c [244];
  undefined1 auStack_878 [2152];
  
  memset(&local_97c,0,0x104);
  memset(auStack_878,0,DAT_000144a4);
  local_a78[0] = param_1;
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000144b0,DAT_000144ac,DAT_000144a8);
  iVar1 = DAT_000144b4;
  *(undefined4 *)(DAT_000144b4 + 4) = 0;
  if (*(int *)(iVar1 + 8) != 0) {
    local_97c = CONCAT31(local_97c._1_3_,0xb);
    local_97c = CONCAT22(1,(undefined2)local_97c);
    local_978 = CONCAT31(local_978._1_3_,(char)param_1);
    memcpy(local_a78,auStack_96c,0xf4);
    SendCmdExpectNoReply(local_97c,local_978,uStack_974,uStack_970);
    return 0;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_000144bc,DAT_000144ac,DAT_000144b8);
  return 2;
}

