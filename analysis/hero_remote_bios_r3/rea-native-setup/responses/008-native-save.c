/* 0x2785c */

/* WARNING: Type propagation algorithm not settling */

longlong FUN_0002785c(longlong param_1,undefined8 *param_2,ulonglong param_3,ulonglong param_4)

{
  short sVar1;
  byte bVar2;
  longlong lVar3;
  short *psVar4;
  short *psVar5;
  wchar_t *pwVar6;
  longlong lVar7;
  longlong lVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  longlong lVar11;
  undefined8 *puVar12;
  longlong local_68;
  short *local_60;
  short *local_58;
  ulonglong local_50 [3];
  
  lVar7 = 0;
  local_58 = (short *)0x0;
  local_50[1] = 0;
  local_60 = (short *)0x0;
  local_50[0] = 0;
  local_68 = 1;
  lVar3 = FUN_00027d00(param_1,(longlong *)&local_58,local_50);
  if (lVar3 < 0) {
    return lVar3;
  }
  if (local_58 == (short *)0x0) {
    return lVar3;
  }
  if ((*(uint *)(param_1 + 0x68) & 0x2000) == 0) {
    lVar7 = FUN_00027e18((longlong *)&local_58,local_50,param_3);
    uVar9 = local_50[0];
    psVar4 = local_58;
    if (lVar7 < 0) {
      return lVar7;
    }
  }
  else {
    psVar4 = (short *)&DAT_0016cfa8;
    lVar3 = lVar7;
    do {
      psVar4 = psVar4 + 1;
      lVar3 = lVar3 + 1;
    } while (*psVar4 != 0);
    psVar5 = (short *)(param_1 + 0x10);
    sVar1 = *psVar5;
    psVar4 = psVar5;
    lVar11 = lVar7;
    while (sVar1 != 0) {
      psVar4 = psVar4 + 1;
      lVar11 = lVar11 + 1;
      sVar1 = *psVar4;
    }
    psVar4 = &DAT_0016cfac;
    lVar8 = lVar7;
    do {
      psVar4 = psVar4 + 1;
      lVar8 = lVar8 + 1;
    } while (*psVar4 != 0);
    uVar9 = local_50[0] + 2 + lVar8 + lVar11 + lVar3;
    psVar4 = (short *)FUN_00001450((longlong)local_58,local_50[0] * 2,uVar9 * 2);
    if (psVar4 == (short *)0x0) {
      return -0x7ffffffffffffff7;
    }
    FUN_000b085c(psVar4,uVar9,(short *)&DAT_0016cfa8);
    FUN_000b085c(psVar4,uVar9,psVar5);
    FUN_000b085c(psVar4,uVar9,&DAT_0016cfac);
    sVar1 = *psVar4;
    psVar5 = psVar4;
    while (sVar1 != 0) {
      psVar5 = psVar5 + 1;
      lVar7 = lVar7 + 1;
      sVar1 = *psVar5;
    }
    uVar9 = lVar7 * 2;
  }
  if ((*(uint *)(param_1 + 0x68) & 0x2000) != 0) {
    local_68 = 0;
    lVar7 = FUN_00001a08((longlong *)&local_60,&local_68,param_2,param_4);
    psVar5 = local_60;
    goto LAB_00027ab8;
  }
  psVar5 = (short *)FUN_000014c8(2);
  if (psVar5 == (short *)0x0) {
    return -0x7ffffffffffffff7;
  }
  uVar10 = param_4 * 2;
  if (uVar10 == 0) {
    puVar12 = param_2;
    local_60 = psVar5;
    lVar3 = FUN_0000199c((longlong)psVar5,&local_68,(longlong)param_2,param_4,0);
    lVar7 = local_68;
    if (lVar3 < 0) {
      if (lVar3 != -0x7ffffffffffffffb) {
        return lVar3;
      }
      goto LAB_00027a41;
    }
  }
  else {
    local_68 = uVar10 + 1;
    local_60 = psVar5;
LAB_00027a41:
    lVar7 = local_68;
    FUN_000013d0((longlong *)&local_60);
    psVar5 = (short *)FUN_000014c8(lVar7 * 2);
    puVar12 = param_2;
    local_60 = psVar5;
    if (psVar5 == (short *)0x0) {
      return -0x7ffffffffffffff7;
    }
  }
  if (lVar7 - 1U < uVar10) {
    return -0x7ffffffffffffffb;
  }
  lVar7 = FUN_0000199c((longlong)psVar5,&local_68,(longlong)puVar12,param_4,uVar10);
LAB_00027ab8:
  lVar3 = 0;
  if (lVar7 < 0) {
    return lVar7;
  }
  if ((*(uint *)(param_1 + 0x68) & 0x2000) == 0) {
    pwVar6 = u__VALUE__0016cfb0;
    do {
      pwVar6 = pwVar6 + 1;
      lVar3 = lVar3 + 1;
    } while (*pwVar6 != L'\0');
    lVar7 = (lVar3 + local_68) * 2;
  }
  else {
    lVar7 = local_68 + 4;
  }
  uVar10 = uVar9 + lVar7;
  psVar4 = (short *)FUN_00001450((longlong)psVar4,uVar9,uVar10);
  if (psVar4 == (short *)0x0) {
    return -0x7ffffffffffffff7;
  }
  local_58 = psVar4;
  if ((*(uint *)(param_1 + 0x68) & 0x2000) == 0) {
    FUN_000b085c(psVar4,uVar10 >> 1,u__VALUE__0016cfb0);
  }
  FUN_000b085c(psVar4,uVar10 >> 1,psVar5);
  if ((*(uint *)(param_1 + 0x68) & 0x2000) != 0) {
    FUN_000b085c(psVar4,uVar10 >> 1,(short *)&DAT_0016cfa8);
  }
  FUN_000013d0((longlong *)&local_60);
  bVar2 = DAT_00190640;
  DAT_00190640 = 1;
  lVar7 = (**(code **)(DAT_00180310 + 0x10))(DAT_00180310,psVar4,local_50 + 1);
  DAT_00190640 = DAT_00190640 & -(bVar2 != 0);
  FUN_000013d0((longlong *)&local_58);
  return lVar7;
}


/* 0x176c */

void FUN_0000176c(undefined8 param_1)

{
  undefined8 local_res10 [3];
  
  local_res10[0] = 0;
  (**(code **)(DAT_00180188 + 0x80))(local_res10,param_1,0,0);
  (**(code **)(DAT_00180188 + 0x90))(local_res10[0],param_1,0);
  return;
}


/* 0x7f7c */

void FUN_00007f7c(void)

{
  ulonglong uVar1;
  byte bVar2;
  
  bVar2 = 0;
  if (DAT_00193880 != 0) {
    uVar1 = 0;
    do {
      if (*(int *)(DAT_00193878 + 4 + uVar1 * 0x48) != 0) break;
      bVar2 = bVar2 + 1;
      uVar1 = (ulonglong)bVar2;
    } while (uVar1 < DAT_00193880);
  }
  if (bVar2 == DAT_00193880) {
    DAT_001801c9 = '\x01';
  }
  if (DAT_001801c9 != '\x01') {
    FUN_0000c5c8(DAT_001938b0,(char)DAT_00193880);
    FUN_000043b4(0xffff0028,FUN_000103ac);
    FUN_00012ac4();
  }
  return;
}


/* 0x44b88 */

undefined1 FUN_00044b2c(void)

{
  undefined1 uVar1;
  wchar_t *pwVar2;
  undefined *puVar3;
  ulonglong uVar4;
  
  puVar3 = &DAT_0010a1e8;
  uVar4 = 0;
  pwVar2 = u_CheckUserPSW_0016e050;
  (**(code **)(DAT_00180198 + 0x48))();
  if ((*DAT_00193620 == '\0') || (DAT_00193620[0x4a] == '\x01')) {
    uVar1 = FUN_0004b1c4(pwVar2,puVar3,uVar4);
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

