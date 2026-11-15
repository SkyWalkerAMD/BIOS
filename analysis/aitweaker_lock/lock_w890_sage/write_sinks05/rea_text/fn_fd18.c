
void WS05_fd18(longlong param_1,undefined *UNRECOVERED_JUMPTABLE)

{
  longlong lVar1;
  ulonglong uVar2;
  ulonglong local_res18;
  ulonglong local_res20;
  
  local_res20 = 0;
  local_res18 = 0;
  lVar1 = WS05_fcb4(param_1,(longlong *)&local_res20,(longlong *)&local_res18);
  uVar2 = local_res20;
  if (lVar1 == 0) {
                    /* WARNING: Could not recover jumptable at 0x0000fd68. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*(code *)UNRECOVERED_JUMPTABLE)();
    return;
  }
  for (; uVar2 <= local_res18; uVar2 = uVar2 + 1) {
    (**(code **)(&DAT_000a9760 + uVar2 * 8))();
  }
  return;
}

