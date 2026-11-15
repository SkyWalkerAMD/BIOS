
undefined4 bios_get_firmware_version(undefined2 param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined1 auStack_100a4 [128];
  undefined2 auStack_10024 [2];
  undefined4 uStack_10020;
  undefined2 uStack_1001c;
  undefined1 auStack_1001a [65538];
  undefined1 local_6;
  
  IDBG_LINUXAPP_DbgOut(0x82,DAT_0001262c,DAT_00012628,DAT_00012624,DAT_00012620);
  memset(auStack_10024,0,DAT_00012630);
  memset(auStack_100a4,0,0x80);
  uVar2 = DAT_00012634;
  if ((param_3 & 0xffff) == 1) {
    local_6 = (undefined1)(param_3 >> 0x10);
    iVar1 = GetBIOSFwVersion(local_6,auStack_100a4);
    uVar2 = DAT_00012638;
    if (iVar1 == 0) {
      memcpy(auStack_1001a,auStack_100a4,0x80);
      uStack_1001c = 0x80;
      goto LAB_000125b4;
    }
  }
  IDBG_LINUXAPP_DbgOut(0x86,uVar2);
  uStack_1001c = 0;
  uStack_10020 = 0xff;
LAB_000125b4:
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

