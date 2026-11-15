
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void Candidate_ACEDxe_NotifySignalList(longlong *param_1)

{
  undefined **ppuVar1;
  undefined **ppuVar2;
  
  FUN_0000e6ec((ulonglong *)&DAT_00016b38);
  ppuVar2 = &PTR_LOOP_00016b50;
  for (ppuVar1 = (undefined **)PTR_LOOP_00016b50; ppuVar1 != ppuVar2;
      ppuVar1 = (undefined **)*ppuVar1) {
    if ((ppuVar1[5] == (undefined *)*param_1) && (ppuVar1[6] == (undefined *)param_1[1])) {
      FUN_0000921c((longlong)(ppuVar1 + -2));
    }
  }
  _DAT_00016b48 = 1;
  Candidate_ACEDxe_RestoreTpl(DAT_00016b40);
  return;
}

