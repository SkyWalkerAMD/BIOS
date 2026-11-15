
ulonglong Candidate_ExtractConfig_Body
                    (longlong param_1,short *param_2,longlong *param_3,longlong *param_4)

{
  short *psVar1;
  ulonglong uVar2;
  short sVar3;
  ulonglong uVar4;
  longlong lVar5;
  wchar_t *pwVar6;
  longlong lVar7;
  longlong lVar8;
  short *psVar9;
  ulonglong local_res8;
  undefined8 local_res10;
  short *local_118 [2];
  short *local_108;
  undefined8 uStack_100;
  longlong local_f8;
  byte local_f0 [24];
  undefined1 local_d8 [160];
  short *psVar10;
  
  lVar8 = 0;
  local_res10 = 0;
  local_f8 = 0;
  if (param_2 == (short *)0x0) {
    local_108 = *(short **)(param_1 + 0x28);
    uStack_100 = *(undefined8 *)(param_1 + 0x30);
    uVar4 = FUN_00001de8(*(longlong *)(param_1 + 0x20),*(char **)(param_1 + 0x18),
                         (longlong *)&local_108,param_4,param_3);
    if ((longlong)uVar4 < 0) {
      return 0x800000000000000e;
    }
    return uVar4;
  }
  uVar4 = (**(code **)(DAT_00043280 + 0x140))(&DAT_00027a80,0,&local_f8);
  if ((longlong)uVar4 < 0) {
    return uVar4;
  }
  lVar5 = lVar8;
  if (param_2 != (short *)PTR_u_GUID__0003cb08) {
    lVar5 = FUN_00000340((char *)param_2,PTR_u_GUID__0003cb08,10);
  }
  if (lVar5 == 0) {
    local_res8 = 0x20;
    FUN_000017bc((longlong)(param_2 + 5),0x20,local_f0);
    psVar9 = param_2 + 0x25;
    if (*psVar9 == 0x26) {
      lVar5 = lVar8;
      if (param_2 + 0x26 != (short *)PTR_u_NAME__0003caf8) {
        lVar5 = FUN_00000340((char *)(param_2 + 0x26),PTR_u_NAME__0003caf8,10);
      }
      if (lVar5 != 0) {
        *param_3 = (longlong)psVar9;
        return 0x8000000000000002;
      }
      local_res8 = 0x50;
      FUN_0000183c((longlong)(param_2 + 0x2b),&local_res8,(longlong)local_d8);
      psVar1 = param_2 + 0x2b + local_res8 * 4;
      if (*psVar1 != 0x26) {
        *param_3 = (longlong)psVar9;
        return 0x8000000000000002;
      }
      local_res8 = 0;
      uVar4 = (**(code **)(DAT_00043290 + 0x48))(local_d8,local_f0,0,&local_res8,local_res10);
      if (uVar4 == 0x8000000000000005) {
        (**(code **)(DAT_00043280 + 0x40))(4,local_res8,&local_res10);
        uVar4 = (**(code **)(DAT_00043290 + 0x48))(local_d8,local_f0,0,&local_res8,local_res10);
      }
      psVar9 = psVar1;
      if ((longlong)uVar4 < 0) {
        *param_3 = (longlong)param_2;
        return uVar4;
      }
      do {
        psVar10 = psVar9 + 1;
        if (*psVar10 == 0x26) {
          if (psVar9 + 2 != (short *)PTR_u_OFFSET__0003cae8) {
            lVar8 = FUN_00000340((char *)(psVar9 + 2),PTR_u_OFFSET__0003cae8,0xe);
          }
          lVar5 = DAT_00043280;
          if (lVar8 != 0) {
            *param_3 = (longlong)psVar10;
            (**(code **)(lVar5 + 0x48))(local_res10);
            return 0x8000000000000002;
          }
          uVar4 = (**(code **)(local_f8 + 0x18))
                            (local_f8,param_2,local_res10,local_res8,param_4,param_3);
          goto LAB_00002539;
        }
        psVar9 = psVar10;
      } while (*psVar10 != 0);
      pwVar6 = u__OFFSET_0_WIDTH__0003ca90;
      lVar5 = lVar8;
      do {
        pwVar6 = pwVar6 + 1;
        lVar5 = lVar5 + 1;
      } while (*pwVar6 != L'\0');
      uVar2 = lVar5 * 2 + 0x12;
      lVar7 = (**(code **)(DAT_00043280 + 0x40))(4,uVar2,local_118);
      lVar5 = DAT_00043280;
      if (lVar7 < 0) {
        *param_3 = (longlong)psVar1;
        (**(code **)(lVar5 + 0x48))(local_res10);
        return 0x8000000000000009;
      }
      (**(code **)(DAT_00043280 + 0x168))(local_118[0],uVar2,0);
      FUN_000193a0((char *)local_118[0],uVar2,(byte *)u__OFFSET_0_WIDTH__x_0003cab8,local_res8);
      sVar3 = *param_2;
      psVar9 = param_2;
      lVar5 = lVar8;
      while (sVar3 != 0) {
        psVar9 = psVar9 + 1;
        lVar5 = lVar5 + 1;
        sVar3 = *psVar9;
      }
      uVar2 = uVar2 + (lVar5 + 1) * 2;
      lVar7 = (**(code **)(DAT_00043280 + 0x40))(4,uVar2,&local_108);
      lVar5 = DAT_00043280;
      if (lVar7 < 0) {
        *param_3 = (longlong)psVar1;
        (**(code **)(lVar5 + 0x48))(local_118[0]);
        uVar4 = 0x8000000000000009;
      }
      else {
        (**(code **)(DAT_00043280 + 0x168))(local_108,uVar2,0);
        uVar4 = FUN_0001a74c(local_108,uVar2,param_2);
        if (((longlong)uVar4 < 0) ||
           (uVar4 = FUN_0001a74c(local_108,uVar2,local_118[0]), (longlong)uVar4 < 0)) {
          *param_3 = (longlong)psVar1;
        }
        else {
          uVar4 = (**(code **)(local_f8 + 0x18))
                            (local_f8,local_108,local_res10,local_res8,param_4,param_3);
          sVar3 = *param_2;
          psVar9 = param_2;
          while (sVar3 != 0) {
            psVar9 = psVar9 + 1;
            lVar8 = lVar8 + 1;
            sVar3 = *psVar9;
          }
          *param_3 = (longlong)(param_2 + lVar8);
        }
        (**(code **)(DAT_00043280 + 0x48))(local_118[0]);
        (**(code **)(DAT_00043280 + 0x48))(local_108);
      }
LAB_00002539:
      (**(code **)(DAT_00043280 + 0x48))(local_res10);
      return uVar4;
    }
  }
  *param_3 = (longlong)param_2;
  return 0x8000000000000002;
}

