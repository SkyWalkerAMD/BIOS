
void Candidate_PasswordTextPrompt
               (short param_1,longlong param_2,ulonglong *param_3,ulonglong *param_4)

{
  short sVar1;
  longlong lVar2;
  short *psVar3;
  short *psVar4;
  ulonglong uVar5;
  byte *pbVar6;
  short *psVar7;
  short *psVar8;
  ulonglong uVar9;
  byte *pbVar10;
  ulonglong uVar11;
  ulonglong *puVar12;
  ushort uVar13;
  ulonglong *puVar14;
  ushort local_res10 [4];
  ulonglong *local_res18;
  ulonglong *local_res20;
  short *local_58;
  short *local_50;
  undefined8 *local_48 [2];
  
  pbVar10 = (byte *)(param_2 + 4);
  psVar8 = (short *)0x0;
  local_res10[0] = 1;
  local_58 = (short *)0x0;
  local_res18 = param_3;
  local_res20 = param_4;
  FUN_00035c88();
  if (DAT_00082638 != 0) {
    (**(code **)(DAT_00082638 + 8))(DAT_00082638,0);
  }
  lVar2 = *(longlong *)(DAT_000824c0 + 0x40);
  if ((lVar2 == 0) ||
     (lVar2 = (**(code **)(lVar2 + 0x18))
                        (lVar2,(longlong)*(int *)(*(longlong *)(lVar2 + 0x48) + 4),local_48,
                         &local_50), lVar2 < 0)) {
    DAT_0006abf0 = IMAGE_DOS_HEADER_00000000.e_program + 0x10;
    DAT_0006abe8 = (short *)0x18;
  }
  else if ((DAT_0006abe8 != local_50) || (DAT_0006abf0 != (byte *)local_48[0])) {
    FUN_00007710();
  }
  FUN_000014a8();
  FUN_00006c38(7);
  FUN_0000704c();
  psVar3 = psVar8;
  if (param_1 != -1) {
    psVar3 = (short *)FUN_00033df4(DAT_00092b30,param_1,(short *)0x0);
  }
  psVar4 = psVar8;
  uVar13 = 1;
  local_50 = psVar3;
  if (psVar3 != (short *)0x0) {
    sVar1 = *psVar3;
    psVar4 = psVar3;
    psVar7 = psVar8;
    while (sVar1 != 0) {
      psVar4 = psVar4 + 1;
      psVar7 = (short *)((longlong)psVar7 + 1);
      sVar1 = *psVar4;
    }
    psVar4 = (short *)FUN_0003ee74((longlong)psVar7 * 2 + 6);
    uVar13 = 1;
    local_58 = psVar4;
    if (psVar4 != (short *)0x0) {
      sVar1 = *psVar3;
      psVar7 = psVar3;
      while (sVar1 != 0) {
        psVar7 = psVar7 + 1;
        psVar8 = (short *)((longlong)psVar8 + 1);
        sVar1 = *psVar7;
      }
      FUN_0000cb44((char *)psVar4,(longlong)psVar8 * 2 + 6,(byte *)u__s_0007bfc8,(ulonglong)psVar3);
      uVar5 = FUN_00034108(psVar4);
      if (pbVar10 < (undefined1 *)(uVar5 / 0x13 + 6)) {
        uVar5 = FUN_00034108(psVar4);
        pbVar10 = (byte *)(uVar5 / 0x13 + 6);
      }
      pbVar6 = DAT_0006abf0 + -2;
      if (pbVar6 <= pbVar10) {
        local_48[0] = FUN_00004e6c(psVar4,(ushort)pbVar6,(short *)local_res10);
        FUN_00005958((longlong *)local_48);
        pbVar10 = pbVar6;
        uVar13 = local_res10[0];
      }
    }
  }
  *param_4 = (longlong)DAT_0006abe8 - 5U >> 1;
  uVar11 = (ulonglong)(DAT_0006abf0 + (-2 - (longlong)pbVar10)) >> 1;
  *param_3 = uVar11;
  uVar5 = *param_4;
  uVar9 = (ulonglong)uVar13;
  FUN_0000c99c(uVar11,uVar5,(ulonglong)pbVar10,uVar9 + 4,0x1f);
  if (pbVar10 != (byte *)0x0) {
    FUN_0000c7f8(uVar11,uVar5,(longlong)pbVar10,uVar9 + 4);
  }
  puVar12 = local_res20;
  puVar14 = local_res18;
  if (psVar4 != (short *)0x0) {
    uVar5 = FUN_00034108(psVar4);
    puVar12 = local_res20;
    puVar14 = local_res18;
    if (DAT_0006abf0 + -2 < (undefined1 *)(uVar5 / 0x13 + 6)) {
      FUN_00004894(*local_res18 + 2,*local_res20,(short)pbVar10 - 3,uVar9,psVar4,0);
    }
    else {
      FUN_00004d40(0,(ulonglong)(DAT_0006abf0 + -2),*local_res20,0,psVar4,0);
      puVar14 = local_res18;
    }
  }
  if (psVar3 != (short *)0x0) {
    FUN_00005958((longlong *)&local_50);
  }
  if (psVar4 != (short *)0x0) {
    FUN_00005958((longlong *)&local_58);
  }
  *puVar14 = ((ulonglong)((longlong)DAT_0006abf0 - (longlong)pbVar10) >> 1) + 1;
  *puVar12 = *puVar12 + uVar9 + 1;
  uVar5 = *puVar12 + 2;
  uVar9 = (*puVar12 - uVar9) - 1;
  if (DAT_0006ac50 == 0xffff) {
    DAT_0006ac50 = uVar9;
  }
  if (DAT_0006ac48 == 0xffff) {
    DAT_0006ac48 = uVar5;
  }
  if (uVar9 < DAT_0006ac50) {
    DAT_0006ac50 = uVar9;
  }
  if (DAT_0006ac48 < uVar5) {
    DAT_0006ac48 = uVar5;
  }
  FUN_0000704c();
  return;
}

