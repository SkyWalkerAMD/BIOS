
undefined8 FUN_000002e0(undefined8 param_1,longlong param_2)

{
  undefined8 local_res8;
  undefined8 local_res10;
  undefined8 local_res18;
  undefined8 local_res20;
  
  DAT_000013d8 = *(longlong *)(param_2 + 0x60);
  local_res8 = 0;
  local_res10 = 0;
  local_res18 = 0;
  local_res20 = 0;
  DAT_000013e0 = *(undefined8 *)(param_2 + 0x58);
  (**(code **)(DAT_000013d8 + 0x50))(0x200,0x10,0x420,0,&local_res8);
  (**(code **)(DAT_000013d8 + 0xa8))(&DAT_000012f0,local_res8,&local_res10);
  (**(code **)(DAT_000013d8 + 0x50))(0x200,0x10,0x650,0,&local_res8);
  (**(code **)(DAT_000013d8 + 0xa8))(&DAT_000012e0,local_res8,&local_res10);
  (**(code **)(DAT_000013d8 + 0x50))(0x200,0x10,0x7dc,0,&local_res8);
  (**(code **)(DAT_000013d8 + 0xa8))(&DAT_000012e0,local_res8,&local_res10);
  (**(code **)(DAT_000013d8 + 0x50))(0x200,0x10,&LAB_00001228,0,&local_res18);
  (**(code **)(DAT_000013d8 + 0xa8))(&DAT_000012e0,local_res18,&local_res20);
  return 0;
}

