undefined8 FUN_0001a18c(longlong *param_1)
{
  ulonglong *puVar1;
  longlong *plVar2;
  longlong lVar3;
  longlong *plVar4;
  uint *puVar5;
  ulonglong uVar6;
  uint uVar7;
  ulonglong uVar8;
  uVar8 = 0;
  if (((DAT_0018f080 == (longlong *)0x0) ||
      (uVar6 = (ulonglong)*DAT_001937f0, uVar6 != DAT_0018f090)) || (DAT_001801a0 < 5)) {
    plVar2 = (longlong *)FUN_000014c8((ulonglong)*DAT_001937f0 << 4);
    if (plVar2 == (longlong *)0x0) {
      DAT_0018f080 = plVar2;
      return 0x8000000000000009;
    }
    uVar6 = uVar8;
    DAT_0018f080 = plVar2;
    if (*DAT_001937f0 != 0) {
      do {
        puVar1 = (ulonglong *)(plVar2 + 1);
        lVar3 = FUN_0001a908(uVar6,puVar1);
        *plVar2 = lVar3;
        if ((*puVar1 != 0) && (lVar3 == 0)) {
          lVar3 = FUN_000014c8(*puVar1);
          *plVar2 = lVar3;
        }
        uVar7 = (int)uVar6 + 1;
        uVar6 = (ulonglong)uVar7;
        plVar2 = plVar2 + 2;
      } while (uVar7 < *DAT_001937f0);
    }
    uVar6 = (ulonglong)*DAT_001937f0;
    DAT_0018f090 = uVar6;
  }
  plVar2 = DAT_0018f080;
  plVar4 = (longlong *)FUN_000014c8(uVar6 << 4);
  *param_1 = (longlong)plVar4;
  if (plVar4 == (longlong *)0x0) {
    return 0x8000000000000009;
  }
  if (plVar2 == (longlong *)0x0) {
    return 0x8000000000000002;
  }
  if (*DAT_001937f0 != 0) {
    plVar2 = plVar2 + 1;
    puVar5 = DAT_001937f0;
    do {
      if ((*plVar4 == 0) && (*plVar2 != 0)) {
        lVar3 = FUN_0000151c(*plVar2);
        *plVar4 = lVar3;
        if (lVar3 == 0) {
          return 0x8000000000000009;
        }
        if (plVar2[-1] != 0) {
          if ((int)uVar8 == 0x12) {
            FUN_000013d0(plVar4);
            FUN_0001ae7c(0x12,0,2,(undefined4 *)plVar2[-1],'\0');
          }
          if (*plVar4 != 0) {
            (**(code **)(DAT_00180188 + 0x160))(*plVar4,plVar2[-1],*plVar2);
          }
        }
        plVar4[1] = *plVar2;
        puVar5 = DAT_001937f0;
      }
      uVar7 = (int)uVar8 + 1;
      uVar8 = (ulonglong)uVar7;
      plVar4 = plVar4 + 2;
      plVar2 = plVar2 + 2;
    } while (uVar7 < *puVar5);
    return 0;
  }
  return 0;
}
