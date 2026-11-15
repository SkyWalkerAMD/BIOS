
void Candidate_ACE_RefreshCacheRecord(longlong *param_1,uint param_2)

{
  undefined8 *puVar1;
  ulonglong local_res18 [2];
  
  puVar1 = FUN_00010f40((ulonglong)param_2,local_res18);
  if (puVar1 != (undefined8 *)0x0) {
    FUN_00005958(param_1);
    param_1[1] = local_res18[0];
    *param_1 = (longlong)puVar1;
  }
  return;
}

