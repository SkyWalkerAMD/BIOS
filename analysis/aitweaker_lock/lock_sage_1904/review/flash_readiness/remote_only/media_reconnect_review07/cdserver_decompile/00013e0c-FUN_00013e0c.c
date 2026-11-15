
void FUN_00013e0c(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  char local_3e;
  char local_3d;
  undefined1 auStack_3c [15];
  char local_2d;
  
  iVar1 = DAT_00013f2c;
  iVar3 = DAT_00013f28;
  local_3e = '\0';
  local_3d = '\0';
  if (*(int *)(DAT_00013f28 + 0x180) == 1) {
    iVar2 = ioctl(*(int *)(DAT_00013f2c + 0x90),DAT_00013f30,&local_3e);
    if (iVar2 < 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00013f4c,DAT_00013f44,DAT_00013f48);
    }
    if ((((local_3e == '\x01') && (iVar2 = IsLmediaRmediaRunning(), iVar2 == 0)) &&
        (iVar2 = IsVirtualMediaRunning(), iVar2 == 0)) &&
       (iVar2 = IsPowerconsumptionmode(), iVar2 == 1)) {
      if (*(int *)(iVar3 + 0x1e4) == 1) {
        iVar3 = racsessinfo_getsessionhdr(auStack_3c);
        if (iVar3 == 0) {
          local_3d = local_2d;
        }
      }
      else {
        iVar3 = get_active_session(1,&local_3d);
        if (iVar3 != 0) {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00013f54,DAT_00013f44,DAT_00013f50);
        }
      }
      if ((local_3d == '\0') && (iVar3 = ioctl(*(int *)(iVar1 + 0x90),DAT_00013f34), iVar3 < 0)) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00013f40,DAT_00013f44,DAT_00013f3c,DAT_00013f38);
      }
    }
  }
  return;
}

