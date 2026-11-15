
undefined8 * FUN_180005704(undefined8 *param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  
  *param_1 = std::exception::vftable;
  uVar1 = *param_2;
  *(undefined1 *)(param_1 + 2) = 0;
  param_1[1] = uVar1;
  return param_1;
}

