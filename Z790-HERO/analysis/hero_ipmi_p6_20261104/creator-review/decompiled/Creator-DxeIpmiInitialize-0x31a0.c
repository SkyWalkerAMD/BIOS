
longlong SelSpacePolicy_observed_calls(longlong param_1,undefined8 param_2)

{
  longlong lVar1;
  ulonglong uVar2;
  undefined1 *puVar3;
  undefined7 uVar4;
  undefined1 local_res8 [16];
  undefined1 local_res18 [8];
  undefined1 local_res20 [8];
  undefined1 local_48;
  byte local_47;
  undefined1 local_44;
  undefined2 local_43;
  char local_40 [4];
  undefined1 local_3c;
  undefined1 local_3b;
  undefined2 local_3a;
  undefined1 local_38;
  undefined1 local_37;
  undefined4 local_36;
  undefined1 local_30 [14];
  byte local_22;
  
  local_44 = 0;
  local_43 = 0;
  local_res20[0] = 3;
  if ((param_1 == 0) || (local_res8[0] = 0xf, 1 < (byte)((char)param_2 - 1U))) {
    lVar1 = -0x7ffffffffffffffe;
  }
  else {
    uVar2 = CONCAT71((int7)((ulonglong)param_2 >> 8),10);
    lVar1 = (**(code **)(param_1 + 8))(param_1,uVar2,0,0x40,0,0,local_30,local_res8);
    if (-1 < lVar1) {
      if ((local_22 & 2) == 0) {
        local_43 = 0;
        uVar2 = uVar2 & 0xffffffffffffff00;
        local_43._1_1_ = 0;
      }
      else {
        puVar3 = &local_44;
        lVar1 = FUN_00003038(param_1,(longlong)puVar3);
        if (lVar1 < 0) {
          return lVar1;
        }
        uVar2 = CONCAT71((int7)((ulonglong)puVar3 >> 8),(undefined1)local_43);
      }
      local_3c = (undefined1)uVar2;
      uVar4 = (undefined7)(uVar2 >> 8);
      if ((char)param_2 == '\x01') {
        local_36 = 0xaa524c43;
        local_res18[0] = 2;
        local_38 = local_3c;
        local_37 = local_43._1_1_;
        lVar1 = (**(code **)(param_1 + 8))
                          (param_1,CONCAT71(uVar4,10),0,0x47,&local_38,6,&local_48,local_res18);
        if ((lVar1 < 0) || ((local_47 & 0xf) != 1)) {
          lVar1 = FUN_00003088(param_1,(longlong)&local_44);
        }
        else {
          lVar1 = 0;
        }
      }
      else {
        if ((local_22 & 8) != 0) {
          local_3a = 0;
          local_3b = local_43._1_1_;
          lVar1 = (**(code **)(param_1 + 8))
                            (param_1,CONCAT71(uVar4,10),0,0x46,&local_3c,4,local_40,local_res20);
          if (lVar1 < 0) {
            return lVar1;
          }
          if (local_40[0] != -0x80) {
            if (local_40[0] != -0x7f) {
              return lVar1;
            }
            return -0x7ffffffffffffffa;
          }
        }
        lVar1 = -0x7ffffffffffffffd;
      }
    }
  }
  return lVar1;
}

