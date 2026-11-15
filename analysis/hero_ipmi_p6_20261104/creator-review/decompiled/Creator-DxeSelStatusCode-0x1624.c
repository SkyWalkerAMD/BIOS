
ulonglong FUN_00001624(undefined8 param_1,undefined8 param_2)

{
  ulonglong uVar1;
  undefined1 local_res10;
  undefined7 uStackX_11;
  undefined1 local_18 [14];
  byte local_a;
  
  _local_res10 = CONCAT71((int7)((ulonglong)param_2 >> 8),0xf);
  uVar1 = 0;
  if ((DAT_00002110 != 0) &&
     (uVar1 = (**(code **)(DAT_00002110 + 8))(DAT_00002110,10,0,0x40,0,0,local_18,&local_res10),
     -1 < (longlong)uVar1)) {
    uVar1 = CONCAT71((int7)(uVar1 >> 8),local_a) & 0xffffffffffffff08;
    DAT_00002090 = (undefined1)uVar1;
    if ((local_a & 0x80) != 0) {
      return CONCAT71((int7)(uVar1 >> 8),1);
    }
  }
  return uVar1 & 0xffffffffffffff00;
}

