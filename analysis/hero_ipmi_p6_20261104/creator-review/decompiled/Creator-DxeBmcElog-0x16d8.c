
longlong FUN_000016d8(longlong param_1,int param_2,byte *param_3,byte *param_4)

{
  longlong lVar1;
  undefined1 local_res8 [8];
  undefined1 local_res10 [8];
  undefined1 local_18;
  byte local_17;
  
  local_res8[0] = 0;
  local_res10[0] = 2;
  if (*(int *)(param_1 + -0x70) == param_2) {
    lVar1 = (**(code **)(DAT_00002040 + 8))(DAT_00002040,6,0,0x2f,0,0,&local_18,local_res10);
    if (-1 < lVar1) {
      if (param_3 == (byte *)0x0) {
        *param_4 = local_17 >> 3 & 1;
      }
      else if ((local_17 >> 3 & 1) != *param_3) {
        local_res10[0] = 1;
        local_17 = local_17 ^ (*param_3 << 3 ^ local_17) & 8;
        lVar1 = (**(code **)(DAT_00002040 + 8))
                          (DAT_00002040,6,0,0x2e,&local_18,2,local_res8,local_res10);
      }
    }
  }
  else {
    lVar1 = -0x7ffffffffffffff2;
  }
  return lVar1;
}

