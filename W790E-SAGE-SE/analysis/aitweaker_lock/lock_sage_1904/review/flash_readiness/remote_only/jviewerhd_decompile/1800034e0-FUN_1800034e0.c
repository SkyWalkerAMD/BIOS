
undefined8 FUN_1800034e0(longlong param_1)

{
  undefined8 uVar1;
  
  uVar1 = FUN_180003470(param_1);
  if ((int)uVar1 != 0) {
    *(undefined4 *)(param_1 + 0x118) = 0x200;
    *(undefined4 *)(param_1 + 0x11c) = 0xb40;
  }
  return 0;
}

