
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void Candidate_ACE1904_schedule_with_ordering(undefined **param_1)

{
  undefined **ppuVar1;
  
  for (ppuVar1 = (undefined **)PTR_LOOP_00016b98; ppuVar1 != &PTR_LOOP_00016b98;
      ppuVar1 = (undefined **)*ppuVar1) {
    if ((((*(char *)(ppuVar1 + 0xb) != '\0') && (*(char *)((longlong)ppuVar1 + 0x6c) != '\0')) &&
        (ppuVar1 + -1 != param_1)) &&
       ((param_1[6] == *(undefined **)((longlong)ppuVar1 + 0x5c) &&
        (param_1[7] == *(undefined **)((longlong)ppuVar1 + 100))))) {
      Candidate_ACE1904_schedule_with_ordering(ppuVar1 + -1);
    }
  }
  FUN_0000e6ec((ulonglong *)&DAT_00016b60);
  *(undefined1 *)((longlong)param_1 + 0x74) = 0;
  ppuVar1 = param_1 + 3;
  *(undefined1 *)((longlong)param_1 + 0x76) = 1;
  *ppuVar1 = (undefined *)&PTR_LOOP_00016b78;
  param_1[4] = PTR_LOOP_00016b80;
  *(undefined ***)PTR_LOOP_00016b80 = ppuVar1;
  _DAT_00016b70 = 1;
  PTR_LOOP_00016b80 = (undefined *)ppuVar1;
  FUN_0000cc98(DAT_00016b68);
  for (ppuVar1 = (undefined **)PTR_LOOP_00016b98; ppuVar1 != &PTR_LOOP_00016b98;
      ppuVar1 = (undefined **)*ppuVar1) {
    if (((*(char *)((longlong)ppuVar1 + 0x59) != '\0') &&
        (*(char *)((longlong)ppuVar1 + 0x6c) != '\0')) &&
       ((ppuVar1 + -1 != param_1 &&
        ((param_1[6] == *(undefined **)((longlong)ppuVar1 + 0x5c) &&
         (param_1[7] == *(undefined **)((longlong)ppuVar1 + 100))))))) {
      Candidate_ACE1904_schedule_with_ordering(ppuVar1 + -1);
    }
  }
  return;
}

