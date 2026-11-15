void FUN_0001b708(longlong *param_1,uint param_2)
{
  longlong lVar1;
  ulonglong local_res18 [2];
  lVar1 = FUN_0001a908((ulonglong)param_2,local_res18);
  if (lVar1 != 0) {
    FUN_000013d0(param_1);
    param_1[1] = local_res18[0];
    *param_1 = lVar1;
  }
  return;
}
