
undefined8
FUN_00016a1c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5)

{
  undefined8 local_res20;
  
  local_res20 = param_4;
  (**(code **)(DAT_0001e070 + 0x50))(0x200,8,0x488,0,&local_res20);
  (**(code **)(DAT_0001e070 + 0xa8))(param_1,local_res20,param_5);
  (**(code **)(DAT_0001e070 + 0x68))(local_res20);
  return local_res20;
}

