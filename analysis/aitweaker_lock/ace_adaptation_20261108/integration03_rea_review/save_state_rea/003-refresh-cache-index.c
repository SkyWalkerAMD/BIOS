
void Candidate_ACE_RefreshCacheIndex(ulonglong param_1)

{
  longlong lVar1;
  
  if ((DAT_00082650 != 0) || (lVar1 = FUN_00010a94(param_1,0), -1 < lVar1)) {
    Candidate_ACE_RefreshCacheRecord
              ((longlong *)((param_1 & 0xffffffff) * 0x10 + DAT_00082650),(uint)param_1);
  }
  return;
}

