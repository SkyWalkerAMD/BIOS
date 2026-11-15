
undefined4 FUN_000181ec(int param_1)

{
  undefined4 uVar1;
  
  if (param_1 < 4) {
    uVar1 = *(undefined4 *)(DAT_00018200 + param_1 * 4);
  }
  else {
    uVar1 = 0xffffffff;
  }
  return uVar1;
}

