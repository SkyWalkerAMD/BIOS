
void FUN_000389e8(longlong param_1)

{
  longlong lVar1;
  longlong lVar2;
  longlong lVar3;
  longlong *plVar4;
  uint uVar5;
  ulonglong uVar6;
  uint uVar7;
  longlong lVar8;
  uint local_res8 [2];
  longlong local_res10;
  
  lVar1 = DAT_001938e0;
  uVar7 = 0;
  local_res8[0] = 0;
  if (DAT_001937e8 != (uint *)0x0) {
    uVar7 = *DAT_001937e8;
  }
  if (DAT_00193628 != 0) {
    FUN_000013d0(&DAT_00193628);
    DAT_00193628 = 0;
  }
  DAT_00193630 = 0;
  lVar2 = FUN_000014c8((ulonglong)(uint)(DAT_00193690 + DAT_001936a0 + DAT_001936b0));
  local_res10 = lVar2;
  (**(code **)(DAT_00180188 + 0x160))(lVar2,DAT_001938e0,DAT_001936a0 + DAT_00193690 + DAT_001936b0)
  ;
  DAT_001802f0 = 1;
  if ((DAT_001938e0 != 0) && (uVar6 = 0, lVar8 = DAT_001938e0, uVar7 != 0)) {
    do {
      plVar4 = (longlong *)((ulonglong)*(uint *)(lVar2 + 4 + uVar6 * 4) + lVar2);
      if ((plVar4 != (longlong *)0x0) && ((*plVar4 != 0 && (*plVar4 != 0xffff)))) {
        if (lVar1 == lVar8) {
          plVar4 = (longlong *)((ulonglong)DAT_001937e8[uVar6 + 1] + lVar8);
        }
        else {
          plVar4 = FUN_00038994(plVar4);
        }
        if (((plVar4 != (longlong *)0x0) && (*plVar4 != 0)) && (*plVar4 != 0xffff)) {
          lVar3 = FUN_00038830((longlong)plVar4,param_1,local_res8);
          lVar8 = DAT_001938e0;
          if (lVar3 == -0x7ffffffffffffffa) {
            uVar6 = (ulonglong)((int)uVar6 - 1);
          }
          else {
            local_res8[0] = 0;
          }
        }
      }
      uVar5 = (int)uVar6 + 1;
      uVar6 = (ulonglong)uVar5;
    } while (uVar5 < uVar7);
  }
  if ((param_1 - 2U < 2) && (DAT_00193630 != 0)) {
    uVar6 = 0;
    if (DAT_00193630 != 0) {
      do {
        FUN_00038bbc(*(longlong *)(DAT_00193628 + uVar6 * 8),3);
        FUN_00038bbc(*(longlong *)(DAT_00193628 + uVar6 * 8),2);
        uVar6 = uVar6 + 1;
      } while (uVar6 < DAT_00193630);
    }
    if (DAT_00193628 != 0) {
      FUN_000013d0(&DAT_00193628);
      DAT_00193628 = 0;
    }
    DAT_00193630 = 0;
  }
  DAT_001802f0 = 0;
  FUN_000013d0(&local_res10);
  return;
}

