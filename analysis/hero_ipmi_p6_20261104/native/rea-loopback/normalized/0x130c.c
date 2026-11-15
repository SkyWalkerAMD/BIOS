longlong FUN_0000130c(undefined8 param_1,undefined8 param_2,undefined4 *param_3,longlong *param_4)
{
  longlong lVar1;
  longlong lVar2;
  undefined4 local_res18 [4];
  longlong local_28 [2];
  local_res18[0] = 0;
  if (param_3 != (undefined4 *)0x0) {
    local_res18[0] = *param_3;
  }
  lVar1 = (**(code **)(DAT_00180198 + 0x48))(param_1,param_2,local_res18,param_4,0);
  if ((lVar1 == -0x7ffffffffffffffb) && (lVar1 = FUN_000014c8(*param_4 + 1), lVar1 != 0)) {
    local_28[0] = lVar1;
    lVar2 = (**(code **)(DAT_00180198 + 0x48))(param_1,param_2,local_res18,param_4,lVar1);
    if (lVar2 < 0) {
      FUN_000013d0(local_28);
      lVar1 = local_28[0];
    }
    if (param_3 != (undefined4 *)0x0) {
      *param_3 = local_res18[0];
    }
  }
  else {
    lVar1 = 0;
  }
  return lVar1;
}
