
ulonglong Candidate_AuthenticationPrompt(uint param_1,longlong *param_2,ulonglong param_3)

{
  short sVar1;
  longlong lVar2;
  undefined8 *puVar3;
  short *psVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  short *psVar7;
  undefined8 uVar8;
  ulonglong uVar9;
  undefined4 *puVar10;
  ulonglong uVar11;
  ulonglong local_res10;
  ulonglong local_res18;
  undefined8 *local_res20;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  short *local_58;
  short *local_50;
  undefined8 local_48;
  undefined8 local_40;
  
  local_b8 = 0x73e7e01;
  uVar9 = 0;
  local_b4 = 0x4e852611;
  local_48 = 0;
  local_40 = 0;
  uVar11 = 0x14;
  local_b0 = 0xb6a396b8;
  local_ac = 0xba7c76;
  local_68 = 0xb9b038b0;
  local_64 = 0x4aabe2b6;
  local_60 = 0x65413594;
  local_5c = 0x32d0feec;
  local_78 = 0xab1404ca;
  local_74 = 0x42084801;
  local_70 = 0xd530bf98;
  local_6c = 0xd3d4da21;
  local_88 = 0x541d5a75;
  local_84 = 0x43c795ee;
  local_80 = 0x94235d9e;
  local_7c = 0x496248dc;
  local_a8 = 0xd69240c0;
  local_a4 = 0x4f2ddd40;
  local_a0 = 0x48486398;
  local_9c = 0x5f616eda;
  local_98 = 0xfdfbbfab;
  local_94 = 0x4961bc61;
  local_90 = 0x447717b9;
  local_8c = 0x7b504156;
  local_res18 = param_3;
  FUN_000064e4(&local_b8);
  DAT_00082658 = 1;
  FUN_00006428(1,0x3051006);
  FUN_00005b0c(0xffff0008,&LAB_000368a4,0,0);
  puVar3 = *(undefined8 **)(DAT_000824c0 + 0x30);
  (*(code *)*puVar3)(puVar3,0);
  puVar3 = FUN_0003eea8(puVar3,0xb71b04);
  local_res20 = puVar3;
  if (puVar3 != (undefined8 *)0x0) {
    (**(code **)(DAT_000824c8 + 0x160))(puVar3,DAT_00092b28);
  }
  local_50 = (short *)FUN_00033df4(DAT_00092b30,0x13,(short *)0x0);
  if (local_50 != (short *)0x0) {
    psVar4 = FUN_00045760(local_50);
    local_58 = psVar4;
    uVar5 = FUN_00034108(psVar4);
    if (0x14 < uVar5 / 0x13) {
      uVar11 = FUN_00034108(psVar4);
      uVar11 = uVar11 / 0x13;
    }
    FUN_00005958((longlong *)&local_50);
    FUN_00005958((longlong *)&local_58);
  }
  Candidate_PasswordTextPrompt(0x12,uVar11,&local_res10,&local_res18);
  uVar8 = 0x2a;
  psVar4 = (short *)FUN_0003ee74(0x2a);
  local_58 = psVar4;
  uVar5 = FUN_000354ac(uVar8);
  lVar2 = *param_2;
  uVar11 = uVar9;
  while (lVar2 != 0) {
    uVar8 = 0x14;
    uVar6 = FUN_0004d118((undefined8 *)psVar4,0x14,local_res10,local_res18);
    if (uVar6 != 0x8000000000000015) {
      puVar3 = local_res20;
      if (uVar6 == 0x8000000000000012) break;
      uVar11 = FUN_00035578(psVar4,uVar8);
      uVar11 = uVar11 & 0xffffffff & uVar5 & 0xffffffff;
      puVar3 = local_res20;
      if (*psVar4 == 0) {
        if (uVar11 != 0) break;
        if (((uVar5 & 1) == 0) && ((param_1 & 1) != 0)) {
          uVar11 = 1;
        }
        if (((uVar5 & 2) == 0) && ((param_1 & 2) != 0)) {
          uVar11 = 2;
        }
      }
      if (uVar11 != 0) break;
      FUN_0004cf74(0x14,0x13,local_res10,local_res18,*param_2 != 1);
      *param_2 = *param_2 + -1;
    }
    puVar3 = local_res20;
    lVar2 = *param_2;
  }
  sVar1 = *psVar4;
  psVar7 = psVar4;
  while (sVar1 != 0) {
    psVar7 = psVar7 + 1;
    uVar9 = uVar9 + 1;
    sVar1 = *psVar7;
  }
  if ((uVar9 < DAT_00082990) && (DAT_00082980 != (short *)0x0)) {
    FUN_0003e700(DAT_00082980,DAT_00082990,psVar4);
  }
  FUN_00005984(&local_58);
  if (uVar11 == 0) {
    FUN_000064e4(&local_a8);
    FUN_00006428(0x80000002,0x3051001);
    FUN_0004cf74(0x14,0x13,local_res10,local_res18,'\0');
    puVar10 = &local_98;
  }
  else {
    FUN_00006c38(7);
    FUN_0000704c();
    if ((uVar5 & 2) == 0) {
      uVar11 = 2;
    }
    FUN_0004c7e4((int)uVar11);
    if (uVar11 == 2) {
      FUN_000064e4(&local_88);
    }
    if (uVar11 != 1) goto LAB_0004cbc1;
    puVar10 = &local_78;
  }
  FUN_000064e4(puVar10);
LAB_0004cbc1:
  FUN_000064e4(&local_68);
  DAT_00082658 = 0;
  if (puVar3 != (undefined8 *)0x0) {
    (**(code **)(DAT_000824c8 + 0x160))(DAT_00092b28,puVar3,0xb71b04);
    FUN_00005958((longlong *)&local_res20);
  }
  return uVar11;
}

