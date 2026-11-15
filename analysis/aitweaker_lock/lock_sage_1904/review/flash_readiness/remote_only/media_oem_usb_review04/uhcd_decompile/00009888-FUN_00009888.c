
longlong FUN_00009888(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  longlong lVar1;
  undefined8 local_res8;
  undefined8 *local_res20;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  local_res20 = (undefined8 *)0x0;
  local_28 = 0x3279a703;
  local_24 = 0x4cbcba93;
  local_20 = 0x2a5c11ad;
  local_1c = 0x804ac982;
  local_res8 = param_1;
  lVar1 = (**(code **)(DAT_000104c0 + 0x98))(param_1,&local_28,&local_res20);
  if ((lVar1 < 0) && (lVar1 = (**(code **)(DAT_000104c0 + 0x40))(4,0x10), -1 < lVar1)) {
    FUN_00000340(local_res20,0x10,0);
    *local_res20 = param_2;
    local_res20[1] = param_3;
    lVar1 = (**(code **)(DAT_000104c0 + 0x80))(&local_res8,&local_28,0,local_res20);
    if (lVar1 < 0) {
      (**(code **)(DAT_000104c0 + 0x48))(local_res20);
    }
  }
  return lVar1;
}

