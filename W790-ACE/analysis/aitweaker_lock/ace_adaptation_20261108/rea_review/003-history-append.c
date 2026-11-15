
longlong Candidate_ACE_HistoryAppend(ushort param_1,ushort param_2)

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
  if (DAT_00082760 == (undefined8 *)0x0) {
    lVar6 = *(longlong *)(*(longlong *)(DAT_00082748 + 0x30) + (ulonglong)param_2 * 8);
    if (*(short *)(lVar6 + 0x32) != 0) {
      return 0;
    }
    DAT_00082758 = *(int *)(DAT_00082748 + 0x2c) + 0x14;
    DAT_00082760 = FUN_0003eea8(lVar6,(ulonglong)DAT_00082758 << 5);
    if (DAT_00082760 == (undefined8 *)0x0) {
      return -0x7ffffffffffffff7;
    }
    DAT_00082754 = (uint)param_2;
  }
  puVar3 = DAT_00082760;
  lVar6 = DAT_00082748;
  local_res10[0] = 0xffffffff;
  uVar4 = (ulonglong)param_2;
  if (*(longlong *)(*(longlong *)(DAT_00082748 + 0x30) + uVar4 * 8) == 0) {
    return -0x7fffffffffffffeb;
  }
  lVar2 = Candidate_ACE_HistoryParent(param_2,local_res8,(int *)local_res10);
  if (lVar2 == -0x7fffffffffffffeb) {
    return -0x7fffffffffffffeb;
  }
  if (lVar2 == 0) {
    if (DAT_00082758 <= local_res10[0]) {
LAB_000103cb:
      if (DAT_00082758 <= DAT_00082778) {
        uVar1 = DAT_00082758 + 0x14;
        uVar5 = (ulonglong)DAT_00082758;
        DAT_00082758 = uVar1;
        puVar3 = FUN_000059dc((longlong)puVar3,uVar5,(ulonglong)uVar1);
        lVar6 = DAT_00082748;
        DAT_00082760 = puVar3;
        if (puVar3 == (undefined8 *)0x0) {
          DAT_00082778 = 0;
          return -0x7ffffffffffffff7;
        }
      }
      lVar6 = *(longlong *)(*(longlong *)(lVar6 + 0x30) + uVar4 * 8);
      if (lVar6 != 0) {
        uVar5 = (ulonglong)DAT_00082778;
        puVar3[uVar5 * 4] = *(undefined8 *)(lVar6 + 0x20);
        *(uint *)(DAT_00082760 + uVar5 * 4 + 1) =
             (uint)*(ushort *)(*(longlong *)(*(longlong *)(DAT_00082748 + 0x30) + uVar4 * 8) + 0x2a)
        ;
        if (DAT_00082778 != 0) {
          DAT_00082760[uVar5 * 4 + 2] = DAT_00082760[(ulonglong)(DAT_00082778 - 1) * 4];
          *(undefined4 *)(DAT_00082760 + uVar5 * 4 + 3) =
               *(undefined4 *)(DAT_00082760 + (ulonglong)(DAT_00082778 - 1) * 4 + 1);
        }
        DAT_00082778 = DAT_00082778 + 1;
        return lVar2;
      }
      return -0x7fffffffffffffeb;
    }
    DAT_00082778 = local_res10[0] + 1;
    if (DAT_00082758 <= DAT_00082778) {
      return 0;
    }
    uVar4 = (ulonglong)(DAT_00082758 - DAT_00082778);
    if (uVar4 == 0) {
      return 0;
    }
    puVar3 = puVar3 + (ulonglong)DAT_00082778 * 4;
  }
  else {
    if ((DAT_00082758 <= local_res10[0]) || (local_res8[0] != 0)) goto LAB_000103cb;
    DAT_00082778 = 1;
    if (DAT_00082758 < 2) {
      DAT_00082778 = 1;
      return lVar2;
    }
    uVar4 = (ulonglong)(DAT_00082758 - 1);
    if (uVar4 == 0) {
      DAT_00082778 = 1;
      return lVar2;
    }
    puVar3 = puVar3 + 4;
  }
  FUN_00000360(puVar3,uVar4 << 5,0);
  return lVar2;
}

