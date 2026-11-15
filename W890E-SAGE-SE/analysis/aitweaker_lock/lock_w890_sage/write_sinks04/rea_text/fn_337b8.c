
undefined8 FUN_000337b8(longlong *param_1,ulonglong *param_2,ulonglong param_3)

{
  short sVar1;
  wchar_t *pwVar2;
  short *psVar3;
  short *psVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  
  uVar6 = 0;
  pwVar2 = u__OFFSET__000a9198;
  uVar7 = uVar6;
  do {
    pwVar2 = pwVar2 + 1;
    uVar7 = uVar7 + 1;
  } while (*pwVar2 != L'\0');
  psVar3 = (short *)&DAT_000a91b0;
  uVar5 = uVar6;
  do {
    psVar3 = psVar3 + 1;
    uVar5 = uVar5 + 1;
  } while (*psVar3 != 0);
  uVar7 = (uVar5 + uVar7) * 2 + 0x22;
  psVar3 = (short *)FUN_00059b50(uVar5,uVar7);
  if (psVar3 != (short *)0x0) {
    FUN_00017908((char *)psVar3,uVar7,(byte *)u__OFFSET__x_WIDTH__x_000a91c0,param_3);
    psVar4 = (short *)*param_1;
    uVar5 = uVar6;
    uVar7 = uVar6;
    if (*psVar4 != 0) {
      do {
        psVar4 = psVar4 + 1;
        uVar7 = uVar7 + 1;
      } while (*psVar4 != 0);
      psVar4 = (short *)*param_1;
      uVar7 = uVar7 * 2;
      do {
        psVar4 = psVar4 + 1;
        uVar5 = uVar5 + 1;
      } while (*psVar4 != 0);
    }
    sVar1 = *psVar3;
    psVar4 = psVar3;
    while (sVar1 != 0) {
      psVar4 = psVar4 + 1;
      uVar6 = uVar6 + 1;
      sVar1 = *psVar4;
    }
    uVar6 = (uVar6 + uVar5) * 2 + 2;
    psVar4 = (short *)FUN_0000fc40(*param_1,uVar7,uVar6);
    *param_1 = (longlong)psVar4;
    if (psVar4 != (short *)0x0) {
      FUN_000592e4(psVar4,uVar6 >> 1,psVar3);
      (**(code **)(DAT_000afbc8 + 0x48))(psVar3);
      *param_2 = uVar6;
      return 0;
    }
  }
  return 0x8000000000000009;
}

