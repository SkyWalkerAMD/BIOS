
longlong FUN_00010220(ushort param_1,ushort param_2)

{
  uint uVar1;
  longlong lVar2;
  undefined8 *puVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  longlong lVar6;
  short local_res8 [4];
  uint local_res10 [2];
  
  local_res8[0] = 0;
  if (param_1 == param_2) {
    return 0;
  }
  if (DAT_000835a0 == (undefined8 *)0x0) {
    lVar6 = *(longlong *)(*(longlong *)(DAT_00083588 + 0x30) + (ulonglong)param_2 * 8);
    if (*(short *)(lVar6 + 0x32) != 0) {
      return 0;
    }
    DAT_00083598 = *(int *)(DAT_00083588 + 0x2c) + 0x14;
    DAT_000835a0 = FUN_0003f714(lVar6,(ulonglong)DAT_00083598 << 5);
    if (DAT_000835a0 == (undefined8 *)0x0) {
      return -0x7ffffffffffffff7;
    }
    DAT_00083594 = (uint)param_2;
  }
  puVar3 = DAT_000835a0;
  lVar6 = DAT_00083588;
  local_res10[0] = 0xffffffff;
  uVar4 = (ulonglong)param_2;
  if (*(longlong *)(*(longlong *)(DAT_00083588 + 0x30) + uVar4 * 8) == 0) {
    return -0x7fffffffffffffeb;
  }
  lVar2 = FUN_0001012c(param_2,local_res8,(int *)local_res10);
  if (lVar2 == -0x7fffffffffffffeb) {
    return -0x7fffffffffffffeb;
  }
  if (lVar2 == 0) {
    if (DAT_00083598 <= local_res10[0]) {
LAB_0001037b:
      if (DAT_00083598 <= DAT_000835b8) {
        uVar1 = DAT_00083598 + 0x14;
        uVar5 = (ulonglong)DAT_00083598;
        DAT_00083598 = uVar1;
        puVar3 = FUN_0000598c((longlong)puVar3,uVar5,(ulonglong)uVar1);
        lVar6 = DAT_00083588;
        DAT_000835a0 = puVar3;
        if (puVar3 == (undefined8 *)0x0) {
          DAT_000835b8 = 0;
          return -0x7ffffffffffffff7;
        }
      }
      lVar6 = *(longlong *)(*(longlong *)(lVar6 + 0x30) + uVar4 * 8);
      if (lVar6 != 0) {
        uVar5 = (ulonglong)DAT_000835b8;
        puVar3[uVar5 * 4] = *(undefined8 *)(lVar6 + 0x20);
        *(uint *)(DAT_000835a0 + uVar5 * 4 + 1) =
             (uint)*(ushort *)(*(longlong *)(*(longlong *)(DAT_00083588 + 0x30) + uVar4 * 8) + 0x2a)
        ;
        if (DAT_000835b8 != 0) {
          DAT_000835a0[uVar5 * 4 + 2] = DAT_000835a0[(ulonglong)(DAT_000835b8 - 1) * 4];
          *(undefined4 *)(DAT_000835a0 + uVar5 * 4 + 3) =
               *(undefined4 *)(DAT_000835a0 + (ulonglong)(DAT_000835b8 - 1) * 4 + 1);
        }
        DAT_000835b8 = DAT_000835b8 + 1;
        return lVar2;
      }
      return -0x7fffffffffffffeb;
    }
    DAT_000835b8 = local_res10[0] + 1;
    if (DAT_00083598 <= DAT_000835b8) {
      return 0;
    }
    uVar4 = (ulonglong)(DAT_00083598 - DAT_000835b8);
    if (uVar4 == 0) {
      return 0;
    }
    puVar3 = puVar3 + (ulonglong)DAT_000835b8 * 4;
  }
  else {
    if ((DAT_00083598 <= local_res10[0]) || (local_res8[0] != 0)) goto LAB_0001037b;
    DAT_000835b8 = 1;
    if (DAT_00083598 < 2) {
      DAT_000835b8 = 1;
      return lVar2;
    }
    uVar4 = (ulonglong)(DAT_00083598 - 1);
    if (uVar4 == 0) {
      DAT_000835b8 = 1;
      return lVar2;
    }
    puVar3 = puVar3 + 4;
  }
  FUN_00000360(puVar3,uVar4 << 5,0);
  return lVar2;
}

