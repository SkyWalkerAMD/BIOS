
longlong entry(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  longlong lVar2;
  undefined8 local_res18;
  undefined1 local_res20 [8];
  
  FUN_00001140(param_1,param_2);
  local_res18 = 0;
  lVar1 = (**(code **)(DAT_000020a0 + 0x50))(0x200,8,&LAB_00001304,0,&local_res18);
  if (-1 < lVar1) {
    lVar2 = (**(code **)(DAT_000020a0 + 0xa8))(&DAT_00002010,local_res18,local_res20);
    lVar1 = 0;
    if (lVar2 < 0) {
      lVar1 = lVar2;
    }
  }
  if (lVar1 < 0) {
    FUN_00001294();
  }
  return lVar1;
}

