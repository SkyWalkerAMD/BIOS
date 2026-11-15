
longlong Observed_QuestionControlInitialize(longlong param_1,longlong param_2)

{
  longlong lVar1;
  
  lVar1 = (*(code *)PTR_FUN_00093ee0)();
  if (-1 < lVar1) {
    if (*(longlong *)(param_2 + 0x28) == 0) {
      lVar1 = -0x7ffffffffffffffd;
    }
    else if ((*(byte *)(param_2 + 0x1c) & 1) == 0) {
      lVar1 = -0x7ffffffffffffffd;
    }
    else {
      (**(code **)(DAT_000afbc8 + 0x160))(param_1 + 0x20,param_2,0x40);
    }
  }
  return lVar1;
}

