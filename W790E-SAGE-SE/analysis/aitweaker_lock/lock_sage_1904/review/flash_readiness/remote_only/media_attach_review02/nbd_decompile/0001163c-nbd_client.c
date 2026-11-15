
undefined4 nbd_client(int param_1)

{
  uint *puVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  
  iVar2 = FUN_0001125c(0,*(undefined4 *)(param_1 + 0x14));
  *(char *)(param_1 + 4) = (char)iVar2;
  *(char *)(param_1 + 5) = (char)((uint)iVar2 >> 8);
  *(char *)(param_1 + 6) = (char)((uint)iVar2 >> 0x10);
  *(char *)(param_1 + 7) = (char)((uint)iVar2 >> 0x18);
  puVar1 = DAT_000119ec;
  if (iVar2 == -1) {
    uVar3 = 0xffffffff;
    if ((*DAT_000119ec & 1) != 0) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00011a38,DAT_00011a10,DAT_00011a34);
    }
  }
  else {
    uVar4 = *DAT_000119ec;
    if ((uVar4 & 1) != 0) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00011a08,DAT_00011a10,DAT_00011a0c,iVar2);
      uVar4 = *puVar1;
    }
    uVar3 = *(undefined4 *)(param_1 + 0x18);
    uVar5 = *(undefined4 *)(param_1 + 0x1c);
    if ((uVar4 & 2) != 0) {
      uVar6 = *(undefined4 *)(param_1 + 0x20);
      uVar7 = *(undefined4 *)(param_1 + 0x24);
      IDBG_LINUXAPP_Runtime_DbgOut
                (0x87,DAT_00011a28,DAT_00011a10,DAT_00011a24,uVar3,uVar5,uVar6,uVar7);
      if ((*puVar1 & 2) == 0) {
        uVar3 = *(undefined4 *)(param_1 + 0x18);
        uVar5 = *(undefined4 *)(param_1 + 0x1c);
      }
      else {
        IDBG_LINUXAPP_Runtime_DbgOut
                  (0x87,DAT_00011a30,DAT_00011a10,DAT_00011a2c,*(undefined2 *)(param_1 + 0x44),uVar5
                   ,uVar6,uVar7);
        uVar3 = *(undefined4 *)(param_1 + 0x18);
        uVar5 = *(undefined4 *)(param_1 + 0x1c);
      }
    }
    ioctl(*(int *)(param_1 + 0x10),DAT_000119f0,uVar3,uVar5);
    ioctl(*(int *)(param_1 + 0x10),DAT_000119f4,*(undefined4 *)(param_1 + 0x20),
          *(undefined4 *)(param_1 + 0x24));
    ioctl(*(int *)(param_1 + 0x10),DAT_000119f8);
    ioctl(*(int *)(param_1 + 0x10),DAT_000119fc,*(byte *)(param_1 + 0x44) & 1);
    ioctl(*(int *)(param_1 + 0x10),DAT_00011a00,0x3c);
    ioctl(*(int *)(param_1 + 0x10),0xab00,*(undefined4 *)(param_1 + 4));
    if ((*puVar1 & 2) != 0) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00011a20,DAT_00011a10,DAT_00011a1c);
    }
    ioctl(*(int *)(param_1 + 0x10),DAT_00011a04);
    uVar3 = 0;
    if ((*puVar1 & 2) != 0) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00011a18,DAT_00011a10,DAT_00011a14);
      return 0;
    }
  }
  return uVar3;
}

