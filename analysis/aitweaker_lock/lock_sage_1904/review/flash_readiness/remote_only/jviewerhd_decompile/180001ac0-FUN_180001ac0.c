
longlong * FUN_180001ac0(longlong *param_1,ulonglong param_2,ulonglong param_3)

{
  code *pcVar1;
  longlong *plVar2;
  longlong *plVar3;
  ulonglong uVar4;
  longlong lVar5;
  
  if ((ulonglong)param_1[2] < param_2) {
    FUN_180004a18("invalid string position");
    pcVar1 = (code *)swi(3);
    plVar2 = (longlong *)(*pcVar1)();
    return plVar2;
  }
  uVar4 = param_1[2] - param_2;
  if (uVar4 < param_3) {
    param_3 = uVar4;
  }
  if (param_3 != 0) {
    plVar2 = param_1;
    plVar3 = param_1;
    if (0xf < (ulonglong)param_1[3]) {
      plVar2 = (longlong *)*param_1;
      plVar3 = (longlong *)*param_1;
    }
    memcpy((void *)((longlong)plVar2 + param_2),(void *)((longlong)plVar3 + param_3 + param_2),
           uVar4 - param_3);
    lVar5 = param_1[2] - param_3;
    param_1[2] = lVar5;
    if (0xf < (ulonglong)param_1[3]) {
      *(undefined1 *)(*param_1 + lVar5) = 0;
      return param_1;
    }
    *(undefined1 *)((longlong)param_1 + lVar5) = 0;
  }
  return param_1;
}

