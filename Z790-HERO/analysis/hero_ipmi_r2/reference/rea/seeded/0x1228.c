
void RegisterPublishCallback_from_event(undefined8 param_1)

{
  longlong lVar1;
  undefined8 local_res18;
  undefined8 local_res20;
  
  local_res18 = 0;
  local_res20 = 0;
  lVar1 = (**(code **)(DAT_000013d8 + 0x50))(0x200,0x10,0xbd8,0,&local_res18);
  if (-1 < lVar1) {
    lVar1 = (**(code **)(DAT_000013d8 + 0xa8))(&DAT_00001300,local_res18,&local_res20);
    if (-1 < lVar1) {
      (**(code **)(DAT_000013d8 + 0x70))(param_1);
    }
  }
  return;
}

