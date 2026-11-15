
void Candidate_GenericHookDispatch(longlong param_1,undefined *UNRECOVERED_JUMPTABLE)

{
  longlong lVar1;
  ulonglong uVar2;
  ulonglong local_res18;
  ulonglong local_res20;
  
  local_res20 = 0;
  local_res18 = 0;
  lVar1 = FUN_00005a54(param_1,(longlong *)&local_res20,(longlong *)&local_res18);
  uVar2 = local_res20;
  if (lVar1 == 0) {
                    /* WARNING: Could not recover jumptable at 0x00005b08. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*(code *)UNRECOVERED_JUMPTABLE)();
    return;
  }
  for (; uVar2 <= local_res18; uVar2 = uVar2 + 1) {
    (**(code **)(&DAT_0007c5e0 + uVar2 * 8))();
  }
  return;
}

