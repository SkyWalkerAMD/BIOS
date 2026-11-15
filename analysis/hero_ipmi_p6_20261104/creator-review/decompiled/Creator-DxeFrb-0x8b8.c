
void FUN_000008b8(void)

{
  longlong lVar1;
  undefined8 local_res18 [2];
  
  local_res18[0] = 0;
  lVar1 = (**(code **)(DAT_000011d0 + 0x140))(&DAT_000010d0,0,local_res18);
  if (-1 < lVar1) {
    if (DAT_00001217 != '\0') {
      FUN_00000708(DAT_000011f0,1);
    }
    if (DAT_0000121a != '\0') {
      FUN_0000084c();
    }
  }
  return;
}

