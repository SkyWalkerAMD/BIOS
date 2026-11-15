
longlong Candidate_ACE_VariableCommit(uint param_1,longlong param_2,ulonglong param_3)

{
  longlong lVar1;
  ulonglong uVar2;
  undefined8 *puVar3;
  
  uVar2 = (ulonglong)param_1;
  lVar1 = -0x7ffffffffffffffe;
  if (((param_2 != 0) && (param_1 < *DAT_00092278)) &&
     (puVar3 = (undefined8 *)((ulonglong)DAT_00092278[uVar2 + 1] + (longlong)DAT_00092278),
     puVar3 != (undefined8 *)0x0)) {
    if ((*(byte *)(puVar3 + 0xd) & 2) == 0) {
      if (((*(uint *)(puVar3 + 0xd) & 0x1000) == 0) &&
         ((0x39 < param_1 || ((0x3ff800003fcfffeU >> (uVar2 & 0x3f) & 1) == 0)))) {
        lVar1 = FUN_0001d928(puVar3,param_2,0,param_3);
      }
      else {
        lVar1 = (**(code **)(DAT_000824d8 + 0x58))
                          (puVar3 + 2,puVar3,*(undefined4 *)(puVar3 + 0xc),param_3,param_2);
      }
      if (lVar1 < 0) {
        return lVar1;
      }
    }
    else {
      lVar1 = 0;
    }
    FUN_00011d8c(uVar2);
  }
  return lVar1;
}

