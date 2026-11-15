
longlong FUN_0000168c(undefined8 param_1)

{
  longlong lVar1;
  longlong lVar2;
  undefined8 local_res8;
  undefined1 local_res10 [8];
  undefined1 local_res18;
  undefined1 local_res20;
  byte local_res21;
  undefined1 local_38;
  undefined2 local_37;
  undefined1 local_34;
  undefined1 local_33;
  undefined4 local_32;
  undefined1 local_28 [14];
  byte local_1a;
  
  lVar1 = DAT_00002110;
  local_38 = 0;
  local_37 = 0;
  local_res18 = 3;
  if (DAT_00002110 == 0) {
    lVar2 = -0x7ffffffffffffffe;
  }
  else {
    local_res10[0] = 0xf;
    local_res8 = param_1;
    lVar2 = (**(code **)(DAT_00002110 + 8))(DAT_00002110,10,0,0x40,0,0,local_28,local_res10);
    if (-1 < lVar2) {
      if ((local_1a & 2) == 0) {
        local_37 = 0;
        local_37._0_1_ = 0;
        local_37._1_1_ = 0;
      }
      else {
        lVar2 = FUN_00001514(lVar1,(longlong)&local_38);
        if (lVar2 < 0) {
          return lVar2;
        }
      }
      local_32 = 0xaa524c43;
      local_res8 = CONCAT71(local_res8._1_7_,2);
      local_34 = (undefined1)local_37;
      local_33 = local_37._1_1_;
      lVar2 = (**(code **)(lVar1 + 8))(lVar1,10,0,0x47,&local_34,6,&local_res20,&local_res8);
      if ((lVar2 < 0) || ((local_res21 & 0xf) != 1)) {
        lVar2 = FUN_00001564(lVar1,(longlong)&local_38);
      }
      else {
        lVar2 = 0;
      }
    }
  }
  return lVar2;
}

