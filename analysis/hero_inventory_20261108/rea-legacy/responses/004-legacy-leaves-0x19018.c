
ulonglong FUN_00018f28(undefined8 *param_1,byte *param_2)

{
  byte bVar1;
  ushort *puVar2;
  ulonglong uVar3;
  longlong lVar4;
  ushort *puVar5;
  uint local_res10 [2];
  ulonglong local_18;
  longlong local_10;
  
  lVar4 = 0;
  local_res10[0] = 3;
  bVar1 = *param_2;
  while (bVar1 != 0) {
    lVar4 = lVar4 + 1;
    bVar1 = param_2[lVar4];
  }
  puVar2 = (ushort *)FUN_00015ad4(lVar4 * 2 + 2);
  puVar5 = puVar2;
  if (puVar2 == (ushort *)0x0) {
    uVar3 = 0x8000000000000009;
  }
  else {
    for (; *param_2 != 0; param_2 = param_2 + 1) {
      *puVar5 = (ushort)*param_2;
      puVar5 = puVar5 + 1;
    }
    *puVar5 = 0;
    local_10 = 0;
    local_18 = 1;
    uVar3 = FUN_0001888c((longlong *)&local_18);
    if ((longlong)uVar3 < 0) {
      (**(code **)(DAT_0001e070 + 0x48))(puVar2);
    }
    else {
      FUN_00018950(&local_18,s_OData_Version_00019b80,&DAT_00019b78);
      uVar3 = FUN_00018af0(param_1,7,(short *)puVar2,&local_18,0,0,(ulonglong *)0x0,(longlong *)0x0,
                           (ulonglong *)0x0,local_res10);
      if ((-1 < (longlong)uVar3) &&
         ((0x15 < local_res10[0] || ((0x200088U >> (local_res10[0] & 0x1f) & 1) == 0)))) {
        uVar3 = 0x8000000000000018;
      }
      if (local_10 != 0) {
        FUN_000188d4(&local_18);
      }
      (**(code **)(DAT_0001e070 + 0x48))(puVar2);
    }
  }
  return uVar3;
}

