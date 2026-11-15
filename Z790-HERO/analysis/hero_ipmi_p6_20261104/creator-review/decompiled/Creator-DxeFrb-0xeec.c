
longlong FUN_00000eec(byte *param_1)

{
  longlong lVar1;
  bool bVar2;
  undefined1 local_res8 [8];
  undefined1 local_res10 [24];
  
  param_1[1] = param_1[1] & 0x8f;
  param_1[3] = param_1[3] | 2;
  bVar2 = DAT_000011c0 == '\0';
  *param_1 = *param_1 & 0x38 | 1;
  param_1[2] = 0;
  local_res8[0] = 1;
  if (bVar2) {
    lVar1 = -0x7ffffffffffffffd;
  }
  else {
    lVar1 = (**(code **)(DAT_00001468 + 8))(DAT_00001468,6,0,0x24,param_1,6,local_res10,local_res8);
    if (-1 < lVar1) {
      local_res10[0] = 0;
      local_res8[0] = 1;
      lVar1 = (**(code **)(DAT_00001468 + 8))(DAT_00001468,6,0,0x22,0,0,local_res10,local_res8);
    }
  }
  return lVar1;
}

