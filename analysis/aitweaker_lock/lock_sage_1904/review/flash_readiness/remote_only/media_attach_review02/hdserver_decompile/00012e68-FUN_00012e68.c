
undefined4 FUN_00012e68(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  bool bVar9;
  
  iVar1 = DAT_000130a8;
  iVar4 = *(int *)(DAT_000130a4 + param_1 * 4);
  iVar3 = *(byte *)(iVar4 + 0x29) - 0x1a;
  switch(iVar3) {
  case 0:
    uVar5 = 0;
    iVar3 = DAT_000130a8 + param_1 * 0x4c;
    *(undefined2 *)(iVar3 + 0x44) = 0;
    if (*(char *)(iVar4 + 0x3f) == -0x80) {
      *(undefined2 *)(iVar3 + 0x44) = 1;
    }
    break;
  default:
    return 0;
  case 0xb:
    uVar2 = *(uint *)(iVar4 + 0x41);
    iVar6 = param_1 * 8;
    iVar7 = DAT_000130a8 + param_1 * 0x4c;
    *(uint *)(iVar7 + 0x18) =
         (uVar2 ^ (uVar2 >> 0x10 | uVar2 << 0x10)) >> 8 & 0xffff00ff ^ (uVar2 >> 8 | uVar2 << 0x18);
    *(undefined4 *)(iVar7 + 0x1c) = 0;
    uVar2 = *(uint *)(iVar4 + 0x3d);
    *(uint *)(iVar7 + 0x20) =
         ((uVar2 ^ (uVar2 >> 0x10 | uVar2 << 0x10)) >> 8 & 0xffff00ff ^ (uVar2 >> 8 | uVar2 << 0x18)
         ) + 1;
    *(undefined4 *)(iVar7 + 0x24) = 0;
    iVar3 = nbd_init(iVar7);
    if (iVar3 == 0) {
      FUN_00017824((*(ushort *)(iVar7 + 0x44) & 1) != 0);
      iVar4 = iVar1 + param_1 * 0x4c;
      FUN_0001780c(0x80);
      iVar3 = FUN_00017dec(*(undefined4 *)(DAT_000130ac + *(int *)(iVar4 + 0x14) * 4));
      *(int *)(DAT_000130b0 + param_1 * 4) = iVar3;
      if (iVar3 == -1) {
        if (*(int *)(iVar4 + 0x14) != -1) {
          nbd_disconnect(iVar7);
          *(undefined4 *)(iVar4 + 0x14) = 0xffffffff;
        }
        goto LAB_00012fac;
      }
      *(undefined4 *)(iVar1 + param_1 * 0x4c) = 1;
      uVar5 = 0;
    }
    else {
      *(undefined4 *)(iVar1 + param_1 * 0x4c) = 0;
      uVar5 = 1;
    }
    break;
  case 0xe:
  case 0x10:
    bVar9 = *(byte *)(iVar4 + 0x29) == 0x28;
    if (bVar9) {
      iVar6 = param_1 * 8;
      iVar3 = param_1 * 9;
    }
    else {
      iVar6 = param_1 << 3;
    }
    if (bVar9) {
      iVar3 = param_1 + iVar3 * 2;
    }
    iVar7 = (iVar6 * 2 + param_1 * 3) * 4;
    if (bVar9) {
      iVar4 = iVar4 + 0x3d;
      iVar3 = DAT_000130a8 + iVar3 * 4;
    }
    iVar8 = DAT_000130a8 + iVar7;
    if (bVar9) {
      *(int *)(iVar3 + 0x48) = iVar4;
    }
    iVar4 = nbd_write_res(iVar8);
    iVar3 = DAT_000130b0;
    if (iVar4 != 0) {
      if (*(int *)(DAT_000130b0 + param_1 * 4) != -1) {
        FUN_000180b4();
        *(undefined4 *)(iVar3 + param_1 * 4) = 0xffffffff;
      }
      iVar3 = iVar1 + iVar6 * 8 + param_1 * 0xc;
      if (*(int *)(iVar3 + 0x14) != -1) {
        nbd_disconnect(iVar8);
        *(undefined4 *)(iVar3 + 0x14) = 0xffffffff;
      }
LAB_00012fac:
      *(undefined4 *)(iVar1 + iVar6 * 8 + param_1 * 0xc) = 0;
      return 1;
    }
    *(undefined4 *)(iVar1 + iVar7) = 1;
    uVar5 = 0;
  }
  return uVar5;
}

