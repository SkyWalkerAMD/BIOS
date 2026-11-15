
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void Candidate_ACEDxe_RestoreTpl(ulonglong param_1)

{
  longlong *plVar1;
  ulonglong uVar2;
  
  while (DAT_00017b10 != 0) {
    DAT_00016b30 = FUN_0000f744(DAT_00017b10);
    if (DAT_00016b30 <= param_1) break;
    if (DAT_00016b30 < 0x1f) {
      FUN_0000cbfc('\x01');
    }
    uVar2 = DAT_00016b30;
    FUN_0000e6ec((ulonglong *)&DAT_00016b38);
    while (plVar1 = (longlong *)(&DAT_0001f340)[uVar2 * 2], plVar1 != &DAT_0001f340 + uVar2 * 2) {
      *(longlong *)(*plVar1 + 8) = plVar1[1];
      *(longlong *)plVar1[1] = *plVar1;
      *plVar1 = 0;
      if ((*(uint *)(plVar1 + -8) & 0x200) != 0) {
        *(undefined4 *)((longlong)plVar1 + -0x3c) = 0;
      }
      _DAT_00016b48 = 1;
      Candidate_ACEDxe_RestoreTpl(DAT_00016b40);
      (*(code *)plVar1[-4])(plVar1 + -9,plVar1[-3]);
      FUN_0000e6ec((ulonglong *)&DAT_00016b38);
    }
    DAT_00017b10 = DAT_00017b10 & ~(1L << (uVar2 & 0x3f));
    _DAT_00016b48 = 1;
    Candidate_ACEDxe_RestoreTpl(DAT_00016b40);
  }
  DAT_00016b30 = param_1;
  if (param_1 < 0x1f) {
    FUN_0000cbfc('\x01');
  }
  return;
}

