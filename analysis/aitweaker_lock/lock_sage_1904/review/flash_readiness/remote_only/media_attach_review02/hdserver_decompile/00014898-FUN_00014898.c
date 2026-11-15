
void FUN_00014898(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  char local_3e;
  char local_3d;
  undefined1 auStack_3c [15];
  char local_2d;
  
  iVar1 = DAT_000149b8;
  iVar3 = DAT_000149b4;
  local_3e = '\0';
  local_3d = '\0';
  if (*(int *)(DAT_000149b4 + 0x180) == 1) {
    iVar2 = ioctl(*(int *)(DAT_000149b8 + 0x21c),DAT_000149bc,&local_3e);
    if (iVar2 < 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000149d8,DAT_000149d0,DAT_000149d4);
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
          IDBG_LINUXAPP_DbgOut(0x82,DAT_000149e0,DAT_000149d0,DAT_000149dc);
        }
      }
      if ((local_3d == '\0') && (iVar3 = ioctl(*(int *)(iVar1 + 0x21c),DAT_000149c0), iVar3 < 0)) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000149cc,DAT_000149d0,DAT_000149c8,DAT_000149c4);
      }
    }
  }
  return;
}

