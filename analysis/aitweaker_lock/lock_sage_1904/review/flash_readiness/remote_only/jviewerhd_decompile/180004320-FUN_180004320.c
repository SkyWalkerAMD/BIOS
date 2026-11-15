
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

void FUN_180004320(int param_1,char *param_2,va_list param_3)

{
  DWORD DVar1;
  ulonglong uVar2;
  longlong lVar3;
  char *pcVar4;
  undefined1 auStack_448 [31];
  char acStack_429 [1025];
  ulonglong local_28;
  
  local_28 = DAT_1800181d0 ^ (ulonglong)auStack_448;
  lVar3 = (longlong)param_1;
  if (DAT_180019610 == 0) {
    FUN_180004300();
  }
  DVar1 = GetCurrentThreadId();
  sprintf(acStack_429 + 1,"[%lu][%s]",(ulonglong)DVar1,(&PTR_s_EMERGENCY_180018110)[lVar3]);
  uVar2 = 0xffffffffffffffff;
  pcVar4 = acStack_429;
  do {
    pcVar4 = pcVar4 + 1;
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
  } while (*pcVar4 != '\0');
  FUN_180006a70(acStack_429 + ~uVar2,param_2,param_3);
  OutputDebugStringA(acStack_429 + 1);
  return;
}

