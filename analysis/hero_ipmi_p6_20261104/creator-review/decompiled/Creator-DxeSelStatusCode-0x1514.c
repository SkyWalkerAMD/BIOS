
undefined8 FUN_00001514(longlong param_1,longlong param_2)

{
  undefined8 uVar1;
  undefined1 local_res8 [32];
  
  if ((param_1 == 0) || (param_2 == 0)) {
    uVar1 = 0x8000000000000002;
  }
  else {
    local_res8[0] = 3;
    uVar1 = (**(code **)(param_1 + 8))(param_1,10,0,0x42,0,0,param_2,local_res8);
  }
  return uVar1;
}

