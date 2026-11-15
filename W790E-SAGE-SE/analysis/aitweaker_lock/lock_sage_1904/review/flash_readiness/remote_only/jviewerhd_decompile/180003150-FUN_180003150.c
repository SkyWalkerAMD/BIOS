
undefined8 FUN_180003150(longlong param_1)

{
  undefined8 uVar1;
  
  uVar1 = FUN_180003130(param_1);
  if (((int)uVar1 == 0) &&
     ((*(char *)(param_1 + 0x26) == '(' || (*(char *)(param_1 + 0x26) == ')')))) {
    return 1;
  }
  return 0;
}

