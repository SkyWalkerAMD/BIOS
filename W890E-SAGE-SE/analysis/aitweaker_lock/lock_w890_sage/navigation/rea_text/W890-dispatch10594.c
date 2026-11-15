
undefined8 FUN_00010594(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  longlong lVar1;
  undefined8 uVar2;
  ulonglong uVar3;
  ulonglong local_28;
  ulonglong local_20;
  
  uVar2 = 0;
  local_20 = 0;
  local_28 = 0;
  lVar1 = FUN_0000fcb4(0xffff0029,(longlong *)&local_20,(longlong *)&local_28);
  uVar3 = local_20;
  if (lVar1 != 0) {
    for (; uVar3 <= local_28; uVar3 = uVar3 + 1) {
      uVar2 = (**(code **)(&DAT_000a9760 + uVar3 * 8))(param_1,param_2,param_3,param_4);
    }
  }
  return uVar2;
}

