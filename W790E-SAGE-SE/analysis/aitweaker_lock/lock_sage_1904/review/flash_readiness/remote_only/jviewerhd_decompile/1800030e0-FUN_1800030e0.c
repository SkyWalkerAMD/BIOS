
undefined8 * FUN_1800030e0(undefined8 *param_1)

{
  *(undefined1 *)(param_1 + 3) = 0;
  *param_1 = CWinNTHarddiskReader::vftable;
  *(undefined8 *)((longlong)param_1 + 0x1c) = 0;
  *(undefined4 *)((longlong)param_1 + 0xc) = 0;
  *(undefined1 *)(param_1 + 2) = 0;
  *(undefined1 *)((longlong)param_1 + 0x24) = 0;
  *(undefined1 *)(param_1 + 0x1e) = 0;
  FUN_180004f80(param_1 + 10,0,0xa0);
  return param_1;
}

