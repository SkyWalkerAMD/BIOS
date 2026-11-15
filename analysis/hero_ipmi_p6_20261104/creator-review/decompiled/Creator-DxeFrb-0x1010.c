
void FUN_00001010(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 **param_4,
                 undefined8 param_5)

{
  undefined8 ***local_res20;
  
  local_res20 = (undefined8 ***)param_4;
  (**(code **)(DAT_000011d0 + 0x50))(0x200,param_2,param_3,0,&param_5);
  local_res20 = &local_res20;
  (**(code **)(DAT_000011d0 + 0xa8))(param_1,param_5,&local_res20);
  return;
}

