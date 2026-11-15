
void FUN_00015514(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 **param_4)

{
  undefined8 local_res18;
  undefined8 ***local_res20;
  
  local_res18 = param_3;
  local_res20 = (undefined8 ***)param_4;
  (**(code **)(DAT_00018a28 + 0x50))(0x200,8,&LAB_00001b40,0,&local_res18);
  local_res20 = &local_res20;
  (**(code **)(DAT_00018a28 + 0xa8))(param_1,local_res18,&local_res20);
  return;
}

