
void WS05_18c0(uint param_1)

{
  longlong lVar1;
  uint local_res8 [2];
  undefined4 local_res10 [2];
  undefined8 local_res18 [2];
  
  local_res8[0] = 0;
  local_res10[0] = 0;
  local_res18[0] = 4;
  lVar1 = (**(code **)(DAT_0001c0e8 + 0x48))
                    (u_AmiEmaIndications_0001a5b0,&DAT_00019388,local_res10,local_res18,local_res8);
  if (lVar1 < 0) {
    local_res10[0] = 7;
  }
  local_res8[0] = local_res8[0] | param_1;
  (**(code **)(DAT_0001c0e8 + 0x58))
            (u_AmiEmaIndications_0001a5b0,&DAT_00019388,local_res10[0],4,local_res8);
  return;
}

