
ulonglong FUN_00001948(longlong param_1,byte *param_2)

{
  ulonglong uVar1;
  undefined1 local_res8 [32];
  undefined1 local_18 [14];
  byte local_a;
  
  local_res8[0] = 0xf;
  uVar1 = (**(code **)(param_1 + 8))(param_1,10,0,0x40,0,0,local_18,local_res8);
  if (-1 < (longlong)uVar1) {
    if (param_2 != (byte *)0x0) {
      uVar1 = CONCAT71((int7)(uVar1 >> 8),local_a) & 0xffffffffffffff08;
      *param_2 = (byte)uVar1;
    }
    if ((local_a & 0x80) != 0) {
      return CONCAT71((int7)(uVar1 >> 8),1);
    }
  }
  return uVar1 & 0xffffffffffffff00;
}

