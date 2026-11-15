
ulonglong FUN_00019114(undefined8 *param_1,short *param_2)

{
  longlong lVar1;
  ulonglong uVar2;
  short *psVar3;
  uint local_res8 [2];
  ulonglong local_18;
  longlong local_10;
  
  lVar1 = 0;
  local_res8[0] = 0;
  if (((param_1 != (undefined8 *)0x0) && (param_2 != (short *)0x0)) &&
     (psVar3 = param_2, *param_2 != 0)) {
    do {
      psVar3 = psVar3 + 1;
      lVar1 = lVar1 + 1;
    } while (*psVar3 != 0);
    if (lVar1 != 0) {
      local_10 = 0;
      local_18 = 1;
      uVar2 = FUN_0001888c((longlong *)&local_18);
      if ((longlong)uVar2 < 0) {
        return uVar2;
      }
      FUN_00018950(&local_18,s_OData_Version_00019b80,&DAT_00019b78);
      uVar2 = FUN_00018af0(param_1,7,param_2,&local_18,0,0,(ulonglong *)0x0,(longlong *)0x0,
                           (ulonglong *)0x0,local_res8);
      if ((-1 < (longlong)uVar2) &&
         ((0x15 < local_res8[0] || ((0x200088U >> (local_res8[0] & 0x1f) & 1) == 0)))) {
        uVar2 = 0x8000000000000018;
      }
      if (local_10 == 0) {
        return uVar2;
      }
      FUN_000188d4(&local_18);
      return uVar2;
    }
  }
  return 0x8000000000000002;
}

