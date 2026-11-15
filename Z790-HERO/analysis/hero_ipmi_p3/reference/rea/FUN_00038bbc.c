
void FUN_00038bbc(longlong param_1,longlong param_2)

{
  uint uVar1;
  longlong lVar2;
  longlong lVar3;
  longlong lVar4;
  longlong *plVar5;
  uint uVar6;
  ulonglong uVar7;
  longlong lVar8;
  uint local_res18 [2];
  longlong local_res20;
  
  lVar2 = DAT_001938e0;
  uVar1 = *DAT_001937e8;
  local_res18[0] = 0;
  lVar3 = FUN_000014c8((ulonglong)(uint)(DAT_001936a0 + DAT_00193690 + DAT_001936b0));
  local_res20 = lVar3;
  (**(code **)(DAT_00180188 + 0x160))(lVar3,DAT_001938e0,DAT_001936a0 + DAT_00193690 + DAT_001936b0)
  ;
  DAT_001802f0 = 1;
  if ((DAT_001938e0 != 0) && (uVar7 = 0, lVar8 = DAT_001938e0, uVar1 != 0)) {
    do {
      plVar5 = (longlong *)((ulonglong)*(uint *)(lVar3 + 4 + uVar7 * 4) + lVar3);
      if ((plVar5 != (longlong *)0x0) &&
         (((*plVar5 != 0 && (*plVar5 != 0xffff)) && (*plVar5 == param_1)))) {
        if (lVar2 == lVar8) {
          plVar5 = (longlong *)((ulonglong)DAT_001937e8[uVar7 + 1] + lVar8);
        }
        else {
          plVar5 = FUN_00038994(plVar5);
        }
        if (((plVar5 != (longlong *)0x0) && (*plVar5 != 0)) && (*plVar5 != 0xffff)) {
          lVar4 = FUN_00038830((longlong)plVar5,param_2,local_res18);
          lVar8 = DAT_001938e0;
          if (lVar4 == -0x7ffffffffffffffa) {
            uVar7 = (ulonglong)((int)uVar7 - 1);
          }
          else {
            local_res18[0] = 0;
          }
        }
      }
      uVar6 = (int)uVar7 + 1;
      uVar7 = (ulonglong)uVar6;
    } while (uVar6 < uVar1);
  }
  DAT_001802f0 = 0;
  FUN_000013d0(&local_res20);
  return;
}

