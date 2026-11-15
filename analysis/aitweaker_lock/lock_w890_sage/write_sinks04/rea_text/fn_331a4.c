
longlong Observed_RouteNativeBuffer
                   (undefined8 *param_1,longlong param_2,ulonglong param_3,ulonglong param_4)

{
  char cVar1;
  longlong lVar2;
  short *psVar3;
  short *psVar4;
  wchar_t *pwVar5;
  short *psVar6;
  short **ppsVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  short sVar10;
  short **ppsVar11;
  ulonglong uVar12;
  short **ppsVar13;
  ulonglong uVar14;
  short **ppsVar15;
  ulonglong local_58;
  short *local_50;
  ulonglong local_48;
  short *local_40;
  undefined8 local_38 [2];
  
  ppsVar7 = (short **)0x0;
  local_50 = (short *)0x0;
  local_38[0] = 0;
  local_40 = (short *)0x0;
  local_48 = 0;
  local_58 = 1;
  lVar2 = FUN_00033688(param_1,(longlong *)&local_50,&local_48);
  if (lVar2 < 0) {
    return lVar2;
  }
  if (local_50 == (short *)0x0) {
    return lVar2;
  }
  if ((*(uint *)(param_1 + 0xd) & 0x2000) == 0) {
    ppsVar7 = &local_50;
    lVar2 = FUN_000337b8((longlong *)ppsVar7,&local_48,param_3);
    uVar12 = local_48;
    psVar3 = local_50;
    if (lVar2 < 0) {
      return lVar2;
    }
  }
  else {
    psVar3 = (short *)&DAT_000a914c;
    ppsVar15 = ppsVar7;
    do {
      psVar3 = psVar3 + 1;
      ppsVar15 = (short **)((longlong)ppsVar15 + 1);
    } while (*psVar3 != 0);
    psVar4 = (short *)(param_1 + 2);
    sVar10 = *psVar4;
    psVar3 = psVar4;
    ppsVar13 = ppsVar7;
    while (sVar10 != 0) {
      psVar3 = psVar3 + 1;
      ppsVar13 = (short **)((longlong)ppsVar13 + 1);
      sVar10 = *psVar3;
    }
    psVar3 = &DAT_000a9150;
    ppsVar11 = ppsVar7;
    do {
      psVar3 = psVar3 + 1;
      ppsVar11 = (short **)((longlong)ppsVar11 + 1);
    } while (*psVar3 != 0);
    uVar12 = (longlong)ppsVar15 + local_48 + 2 + (longlong)ppsVar11 + (longlong)ppsVar13;
    psVar3 = (short *)FUN_0000fc40((longlong)local_50,local_48 * 2,uVar12 * 2);
    if (psVar3 == (short *)0x0) {
      return -0x7ffffffffffffff7;
    }
    FUN_000592e4(psVar3,uVar12,(short *)&DAT_000a914c);
    FUN_000592e4(psVar3,uVar12,psVar4);
    FUN_000592e4(psVar3,uVar12,&DAT_000a9150);
    sVar10 = *psVar3;
    psVar4 = psVar3;
    while (sVar10 != 0) {
      psVar4 = psVar4 + 1;
      ppsVar7 = (short **)((longlong)ppsVar7 + 1);
      sVar10 = *psVar4;
    }
    uVar12 = (longlong)ppsVar7 * 2;
  }
  if ((*(uint *)(param_1 + 0xd) & 0x2000) == 0) {
    psVar4 = (short *)FUN_00059b50(ppsVar7,2);
    if (psVar4 == (short *)0x0) {
      return -0x7ffffffffffffff7;
    }
    lVar2 = FUN_00010950((longlong)psVar4,(longlong *)&local_58,param_2,param_4);
    if (lVar2 < 0) {
      if (lVar2 != -0x7ffffffffffffffb) {
        return lVar2;
      }
      (**(code **)(DAT_000afbc8 + 0x48))();
      psVar4 = (short *)FUN_00059b50(psVar4,local_58 * 2);
      if (psVar4 == (short *)0x0) {
        return -0x7ffffffffffffff7;
      }
    }
    lVar2 = FUN_00010950((longlong)psVar4,(longlong *)&local_58,param_2,param_4);
  }
  else {
    local_58 = 0;
    lVar2 = FUN_000109ec(&local_40,&local_58,param_2,param_4);
    psVar4 = local_40;
  }
  uVar9 = 0;
  if (lVar2 < 0) {
    return lVar2;
  }
  if ((*(uint *)(param_1 + 0xd) & 0x2000) == 0) {
    pwVar5 = u__VALUE__000a9158;
    uVar8 = uVar9;
    do {
      pwVar5 = pwVar5 + 1;
      uVar8 = uVar8 + 1;
    } while (*pwVar5 != L'\0');
    lVar2 = (uVar8 + local_58) * 2;
  }
  else {
    lVar2 = local_58 + 4;
  }
  psVar3 = (short *)FUN_0000fc40((longlong)psVar3,uVar12,uVar12 + lVar2);
  if (psVar3 == (short *)0x0) {
    return -0x7ffffffffffffff7;
  }
  uVar12 = uVar12 + lVar2 >> 1;
  if ((*(uint *)(param_1 + 0xd) & 0x2000) == 0) {
    FUN_000592e4(psVar3,uVar12,u__VALUE__000a9158);
  }
  uVar8 = FUN_00059210(psVar3,uVar12);
  uVar14 = uVar12 - uVar8;
  if (((psVar4 == (short *)0x0) || (99999999 < uVar12 - 1)) || (uVar14 == 0)) goto LAB_000334bf;
  sVar10 = *psVar4;
  if (sVar10 != 0) {
    do {
      if (uVar14 - 1 <= uVar9) goto LAB_000334bf;
      uVar9 = uVar9 + 1;
    } while (psVar4[uVar9] != 0);
  }
  if (uVar14 <= uVar9) goto LAB_000334bf;
  if (psVar3 < psVar4) {
LAB_00033493:
    if (psVar4 < psVar3 + uVar12) goto LAB_000334bf;
  }
  else {
    if (psVar3 < psVar4 + uVar9 + 1) goto LAB_000334bf;
    if (psVar3 <= psVar4) goto LAB_00033493;
  }
  psVar6 = psVar3 + uVar8;
  if (sVar10 != 0) {
    lVar2 = (longlong)psVar4 - (longlong)psVar6;
    do {
      *psVar6 = sVar10;
      psVar6 = psVar6 + 1;
      sVar10 = *(short *)(lVar2 + (longlong)psVar6);
    } while (sVar10 != 0);
  }
  *psVar6 = 0;
LAB_000334bf:
  if ((*(uint *)(param_1 + 0xd) & 0x2000) != 0) {
    FUN_000592e4(psVar3,uVar12,(short *)&DAT_000a914c);
  }
  if (psVar4 != (short *)0x0) {
    (**(code **)(DAT_000afbc8 + 0x48))(psVar4);
  }
  cVar1 = DAT_000afff8;
  DAT_000afff8 = 1;
  lVar2 = (**(code **)(DAT_000afc28 + 0x10))(DAT_000afc28,psVar3,local_38);
  DAT_000afff8 = DAT_000afff8 & -(cVar1 != '\0');
  (**(code **)(DAT_000afbc8 + 0x48))(psVar3);
  return lVar2;
}

