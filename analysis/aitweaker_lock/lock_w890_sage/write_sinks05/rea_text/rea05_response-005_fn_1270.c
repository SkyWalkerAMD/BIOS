
void WS05_1270(longlong param_1)

{
  longlong lVar1;
  undefined1 local_res8 [16];
  undefined8 local_res18;
  undefined8 local_res20;
  undefined4 local_208;
  undefined4 uStack_204;
  undefined4 uStack_200;
  undefined4 uStack_1fc;
  longlong local_1f8 [2];
  undefined4 local_1e8;
  undefined4 uStack_1e4;
  undefined4 uStack_1e0;
  undefined4 uStack_1dc;
  undefined1 local_1d8 [464];
  
  local_res20 = 0;
  local_res18 = 0x1cb;
  local_208 = 0xec87d643;
  uStack_204 = 0x4bb5eba4;
  uStack_200 = 0x3e3fe5a1;
  uStack_1fc = 0xa90db236;
  if (param_1 != 0) {
    (**(code **)(DAT_00004b10 + 0x70))();
  }
  lVar1 = (**(code **)(DAT_00004b10 + 0x140))(&DAT_00004098,0,local_1f8);
  if (-1 < lVar1) {
    local_1e8 = local_208;
    uStack_1e4 = uStack_204;
    uStack_1e0 = uStack_200;
    uStack_1dc = uStack_1fc;
    lVar1 = (**(code **)(local_1f8[0] + 0x20))
                      (u_Setup_000043a8,&local_1e8,&local_res20,&local_res18);
    if (-1 < lVar1) {
      (**(code **)(DAT_00004b18 + 0x48))
                (u_Setup_000043a8,&local_208,local_res8,&local_res18,local_1d8);
    }
  }
  return;
}

