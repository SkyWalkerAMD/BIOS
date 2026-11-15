
undefined4 RebootHost(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined1 local_24 [4];
  undefined1 auStack_20 [4];
  undefined4 local_1c;
  undefined1 uStack_18;
  byte local_17;
  
  local_1c = 5;
  iVar1 = SendRawIPMICommand(0,1,0,0,&uStack_18,&local_1c,0x1e);
  if (iVar1 == 0) {
    if ((local_17 & 1) == 0) {
      local_24[0] = 1;
      local_1c = 1;
      iVar1 = SendRawIPMICommand(0,2,local_24,1,auStack_20,&local_1c,0x1e);
      if (iVar1 != 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000111d0,DAT_000111c4,0x90);
        return 0xffffffff;
      }
    }
    else {
      local_24[0] = 2;
      local_1c = 1;
      iVar1 = SendRawIPMICommand(0,2,local_24,1,auStack_20,&local_1c,0x1e);
      if (iVar1 != 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000111c8,DAT_000111c4,0x84);
        return 0xffffffff;
      }
    }
    uVar2 = 0;
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000111cc,DAT_000111c4,0x76,0,1);
    uVar2 = 0xffffffff;
  }
  return uVar2;
}

