
undefined8 * FUN_180001a60(undefined8 *param_1,undefined1 param_2,undefined1 param_3)

{
  *(undefined1 *)((longlong)param_1 + 0x13a) = param_2;
  *(undefined1 *)((longlong)param_1 + 0x13b) = param_3;
  *param_1 = CHarddiskImgFileReader::vftable;
  *(undefined4 *)((longlong)param_1 + 0xc) = 0;
  *(undefined1 *)(param_1 + 2) = 0;
  *(undefined1 *)((longlong)param_1 + 0x139) = 0;
  param_1[0x24] = 0;
  return param_1;
}

