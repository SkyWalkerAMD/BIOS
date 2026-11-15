
void WS05_10704(undefined8 param_1)

{
  undefined8 local_res10 [3];
  
  local_res10[0] = 0;
  (**(code **)(DAT_000afbc8 + 0x80))(local_res10,param_1,0,0);
  (**(code **)(DAT_000afbc8 + 0x90))(local_res10[0],param_1,0);
  return;
}

