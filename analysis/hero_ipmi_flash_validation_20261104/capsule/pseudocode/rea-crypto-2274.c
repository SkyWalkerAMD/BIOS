
void FUN_00002274(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  undefined8 local_res8 [2];
  undefined8 local_res18 [2];
  
  if (DAT_0000eab0 == 0) {
    DAT_0000ea60 = *(longlong *)(param_2 + 0x60);
    DAT_0000ea98 = *(longlong *)(param_2 + 0x58);
    DAT_0000eab0 = param_2;
  }
  local_res8[0] = param_1;
  if ((DAT_0000eaa0 != (undefined8 *)0x0) ||
     (lVar1 = (**(code **)(DAT_0000ea60 + 0x140))(&DAT_0000e168,0,&DAT_0000eaa0), -1 < lVar1)) {
    (*(code *)*DAT_0000eaa0)(DAT_0000eaa0,local_res8);
    if (((char)local_res8[0] != '\0') &&
       (lVar1 = (*(code *)DAT_0000eaa0[1])(DAT_0000eaa0,&DAT_0000ea68), -1 < lVar1)) {
      lVar1 = FUN_000026d0();
      DAT_0000ea70 = 1;
      if (lVar1 != 0) {
        DAT_0000ea98 = lVar1;
      }
      DAT_0000ea80 = 0;
      FUN_00002564();
      FUN_000025ec();
      DAT_0000ea80 = 1;
    }
  }
  FUN_000021f4(param_2);
  local_res18[0] = 0;
  (**(code **)(DAT_0000ea68 + 0xa8))(local_res18,&DAT_0000e060,0,&PTR_LAB_0000e110);
  return;
}

