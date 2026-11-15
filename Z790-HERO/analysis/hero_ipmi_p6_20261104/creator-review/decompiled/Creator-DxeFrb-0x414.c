
undefined8 FUN_00000414(undefined8 param_1,int param_2,ulonglong *param_3)

{
  ulonglong uVar1;
  undefined1 auVar2 [16];
  longlong lVar3;
  
  if (2 < param_2 - 1U) {
    return 0x8000000000000003;
  }
  uVar1 = *param_3;
  if (uVar1 == 0) {
    return 0x8000000000000002;
  }
  auVar2._8_8_ = 0;
  auVar2._0_8_ = uVar1;
  lVar3 = SUB168(ZEXT816(0x4f8b588e368f0847) * auVar2,8);
  *(short *)(&DAT_00001480 + (longlong)param_2 * 6) = (short)((uVar1 - lVar3 >> 1) + lVar3 >> 0x10);
  return 0;
}

