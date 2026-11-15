
undefined4 nbd_write_res(int param_1)

{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  undefined4 local_30;
  undefined4 local_2c;
  uint local_28;
  uint local_24;
  
  puVar2 = DAT_00012a84;
  uVar5 = *(uint *)(param_1 + 0x28);
  uVar1 = *(uint *)(param_1 + 0x2c);
  local_24 = (uVar5 ^ (uVar5 >> 0x10 | uVar5 << 0x10)) >> 8 & 0xffff00ff ^
             (uVar5 >> 8 | uVar5 << 0x18);
  local_28 = (uVar1 ^ (uVar1 >> 0x10 | uVar1 << 0x10)) >> 8 & 0xffff00ff ^
             (uVar1 >> 8 | uVar1 << 0x18);
  local_2c = 0;
  local_30 = DAT_00012a88;
  if ((*DAT_00012a84 & 2) != 0) {
    uVar4 = DAT_00012a90;
    if (*(short *)(param_1 + 0x46) == 1) {
      uVar4 = DAT_00012a8c;
    }
    IDBG_LINUXAPP_Runtime_DbgOut
              (0x87,DAT_00012a98,DAT_00012a94,0x248,uVar4,*(undefined4 *)(param_1 + 0x14),uVar5,
               uVar1,*(undefined4 *)(param_1 + 0x30),*(undefined4 *)(param_1 + 0x34),
               *(undefined4 *)(param_1 + 0x40));
  }
  iVar3 = FUN_0001119c(*(undefined4 *)(param_1 + 8),&local_30,0x10);
  if (iVar3 == 0) {
    uVar4 = 0;
    if (*(short *)(param_1 + 0x46) != 1) {
      iVar3 = FUN_0001119c(*(undefined4 *)(param_1 + 8),*(undefined4 *)(param_1 + 0x48),
                           *(undefined4 *)(param_1 + 0x40));
      if (iVar3 == 0) {
        uVar5 = *(uint *)(param_1 + 0x38) + *(uint *)(param_1 + 0x40);
        iVar3 = *(int *)(param_1 + 0x3c) +
                (uint)CARRY4(*(uint *)(param_1 + 0x38),*(uint *)(param_1 + 0x40));
        if (iVar3 == 0 && uVar5 < 0x1400001) {
          *(char *)(param_1 + 0x39) = (char)(uVar5 >> 8);
          *(char *)(param_1 + 0x3a) = (char)(uVar5 >> 0x10);
          *(char *)(param_1 + 0x3b) = (char)(uVar5 >> 0x18);
          *(char *)(param_1 + 0x38) = (char)uVar5;
          *(char *)(param_1 + 0x3c) = (char)iVar3;
          *(char *)(param_1 + 0x3d) = (char)((uint)iVar3 >> 8);
          *(char *)(param_1 + 0x3e) = (char)((uint)iVar3 >> 0x10);
          *(char *)(param_1 + 0x3f) = (char)((uint)iVar3 >> 0x18);
          return 0;
        }
        uVar5 = *(uint *)(param_1 + 0x30);
        iVar3 = *(int *)(param_1 + 0x34) - (uint)(uVar5 < 0xa00000);
        uVar1 = uVar5 - 0xa00000;
        if (iVar3 == 0 && uVar5 - 0xa00000 < 0xa00001) {
          iVar3 = *(int *)(param_1 + 0x34);
          uVar1 = uVar5;
        }
        *(undefined1 *)(param_1 + 0x38) = 0;
        *(undefined1 *)(param_1 + 0x39) = 0;
        *(undefined1 *)(param_1 + 0x3a) = 0;
        *(undefined1 *)(param_1 + 0x3b) = 0;
        *(undefined1 *)(param_1 + 0x3c) = 0;
        *(undefined1 *)(param_1 + 0x3d) = 0;
        *(undefined1 *)(param_1 + 0x3e) = 0;
        *(undefined1 *)(param_1 + 0x3f) = 0;
        iVar6 = iVar3;
        posix_fadvise64(*(int *)(param_1 + 0x10),0,CONCAT44(iVar3,uVar1),4);
        if ((*puVar2 & 2) != 0) {
          IDBG_LINUXAPP_Runtime_DbgOut
                    (0x87,DAT_00012a9c,DAT_00012a94,0x270,*(undefined4 *)(param_1 + 0x14),iVar6,
                     uVar1,iVar3,*(undefined4 *)(param_1 + 0x30),*(undefined4 *)(param_1 + 0x34),
                     *(undefined4 *)(param_1 + 0x38),*(undefined4 *)(param_1 + 0x3c));
          return 0;
        }
      }
      else {
        IDBG_LINUXAPP_DbgOut
                  (0x82,DAT_00012aa8,DAT_00012a94,DAT_00012aa4,*(undefined4 *)(param_1 + 0x14));
        uVar4 = 0xffffffff;
      }
    }
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00012aa0,DAT_00012a94,0x24c,*(undefined4 *)(param_1 + 0x14));
    uVar4 = 0xffffffff;
  }
  return uVar4;
}

