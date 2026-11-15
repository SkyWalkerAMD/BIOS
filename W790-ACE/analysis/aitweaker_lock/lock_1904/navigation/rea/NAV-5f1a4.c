
void Candidate_OtherToken45(short *param_1)

{
  undefined8 *puVar1;
  short *psVar2;
  wchar_t wVar3;
  int iVar4;
  short **ppsVar5;
  short **ppsVar6;
  short **ppsVar7;
  short **ppsVar8;
  longlong lVar9;
  undefined8 uVar10;
  longlong lVar11;
  wchar_t *pwVar12;
  int iVar13;
  short *psVar14;
  wchar_t *pwVar15;
  short *local_res8;
  
  puVar1 = DAT_0008b520;
  ppsVar8 = (short **)0x0;
  local_res8 = param_1;
  if (DAT_0008b520 == (undefined8 *)0x0) {
    lVar11 = 3;
    pwVar15 = u_No_Entry_Found_0007fea0;
    pwVar12 = u_Attributes_00078bb0;
    iVar13 = 4;
    goto LAB_0005f640;
  }
  iVar13 = 4;
  lVar11 = 4;
  lVar9 = lVar11;
  if (DAT_0008b528 == '\0') {
    local_res8 = FUN_00068cbc(0,4,(short *)0x0,(short *)0x0);
    ppsVar5 = &local_res8;
    FUN_0005fd58((longlong *)ppsVar5);
    DAT_0008b528 = '\x01';
  }
  else {
    local_res8 = FUN_00068cbc(0,4,(short *)0x0,(short *)0x0);
    ppsVar5 = &local_res8;
    FUN_0005fd58((longlong *)ppsVar5);
  }
  psVar14 = (short *)puVar1[3];
  if ((psVar14 != (short *)0x0) &&
     (psVar2 = psVar14, ppsVar5 = ppsVar8, ppsVar6 = ppsVar8, *psVar14 != 0)) {
    do {
      psVar2 = psVar2 + 1;
      ppsVar6 = (short **)((longlong)ppsVar6 + 1);
    } while (*psVar2 != 0);
    ppsVar5 = (short **)0x0;
    if (ppsVar6 != (short **)0x0) {
      lVar9 = 5;
      local_res8 = FUN_00068cbc(4,5,u_AttributeName_00078db0,psVar14);
      ppsVar5 = &local_res8;
      FUN_0005fd58((longlong *)ppsVar5);
    }
  }
  if (puVar1[1] != 0) {
    FUN_00060080(ppsVar5,lVar9,5,u_DisplayName_00078cb0,puVar1[1]);
  }
  if (puVar1[2] != 0) {
    FUN_00060080(ppsVar5,lVar9,5,u_HelpText_00078eb0,puVar1[2]);
  }
  if ((short *)puVar1[0x14] != (short *)0x0) {
    local_res8 = FUN_00068cbc(4,5,u_UefiNamespaceId_00079cb0,(short *)puVar1[0x14]);
    FUN_0005fd58((longlong *)&local_res8);
  }
  pwVar12 = u_false_0007c3b0;
  pwVar15 = u_false_0007c3b0;
  if (*(char *)(puVar1 + 4) == '\x01') {
    pwVar15 = &DAT_0007c3a0;
  }
  local_res8 = FUN_00068cbc(5,5,u_ReadOnly_00078fb0,pwVar15);
  FUN_0005fd58((longlong *)&local_res8);
  if (*(char *)((longlong)puVar1 + 0x99) == '\x01') {
    pwVar12 = &DAT_0007c3a0;
  }
  local_res8 = FUN_00068cbc(5,5,u_ResetRequired_00079bb0,pwVar12);
  FUN_0005fd58((longlong *)&local_res8);
  local_res8 = FUN_00068cbc(4,5,u_Type_000790b0,
                            u_String_00079de0 + (longlong)*(int *)((longlong)puVar1 + 0x24) * 0x32);
  FUN_0005fd58((longlong *)&local_res8);
  if (((*(int *)((longlong)puVar1 + 0x24) != 10) && (puVar1[5] != 0)) && (puVar1[6] != 0)) {
    local_res8 = FUN_00068cbc(2,5,u_Value_000791b0,(short *)0x0);
    FUN_0005fd58((longlong *)&local_res8);
    ppsVar5 = ppsVar8;
    ppsVar6 = ppsVar8;
    if (puVar1[6] != 0) {
      do {
        lVar9 = puVar1[5];
        uVar10 = 6;
        local_res8 = FUN_00068cbc(0,6,(short *)0x0,(short *)0x0);
        ppsVar7 = &local_res8;
        FUN_0005fd58((longlong *)ppsVar7);
        psVar14 = (short *)((longlong)&IMAGE_DOS_HEADER_00000000.e_crlc + 1);
        FUN_00060080(ppsVar7,uVar10,7,u_ValueDisplayName_000792b0,
                     *(longlong *)((longlong)ppsVar5 + lVar9));
        if (*(int *)((longlong)puVar1 + 0x24) == 10) {
          iVar4 = 5;
LAB_0005f45b:
          local_res8 = FUN_00068cbc(iVar4,7,u_ValueName_000793b0,
                                    *(short **)((longlong)ppsVar5 + lVar9 + 8));
          FUN_0005fd58((longlong *)&local_res8);
        }
        else {
          wVar3 = L'E';
          pwVar15 = u_String_00079de0 + (longlong)*(int *)((longlong)puVar1 + 0x24) * 0x32;
          pwVar12 = u_Enumeration_0007fe28;
          do {
            if (wVar3 != *pwVar15) break;
            pwVar12 = pwVar12 + 1;
            pwVar15 = pwVar15 + 1;
            wVar3 = *pwVar12;
          } while (wVar3 != L'\0');
          iVar4 = iVar13;
          if (*pwVar12 != *pwVar15) goto LAB_0005f45b;
          FUN_0005fee8((ulonglong)(ushort)*pwVar12,pwVar15,psVar14,u_ValueName_000793b0,
                       *(longlong *)((longlong)ppsVar5 + lVar9),(short *)puVar1[3]);
        }
        local_res8 = FUN_00068cbc(1,6,(short *)0x0,(short *)0x0);
        FUN_0005fd58((longlong *)&local_res8);
        ppsVar6 = (short **)((longlong)ppsVar6 + 1);
        ppsVar5 = ppsVar5 + 2;
      } while (ppsVar6 < (short **)puVar1[6]);
    }
    local_res8 = FUN_00068cbc(3,5,(short *)0x0,(short *)0x0);
    FUN_0005fd58((longlong *)&local_res8);
  }
  if ((short *)puVar1[8] != (short *)0x0) {
    local_res8 = FUN_00068cbc(5,5,u_UpperBound_000795b0,(short *)puVar1[8]);
    FUN_0005fd58((longlong *)&local_res8);
  }
  if ((short *)puVar1[9] != (short *)0x0) {
    local_res8 = FUN_00068cbc(5,5,u_LowerBound_000796b0,(short *)puVar1[9]);
    FUN_0005fd58((longlong *)&local_res8);
  }
  if ((short *)puVar1[10] != (short *)0x0) {
    local_res8 = FUN_00068cbc(5,5,u_ScalarIncrement_000797b0,(short *)puVar1[10]);
    FUN_0005fd58((longlong *)&local_res8);
  }
  if ((short *)puVar1[0xb] != (short *)0x0) {
    local_res8 = FUN_00068cbc(5,5,u_MinLength_000798b0,(short *)puVar1[0xb]);
    FUN_0005fd58((longlong *)&local_res8);
  }
  if ((short *)puVar1[0xc] != (short *)0x0) {
    local_res8 = FUN_00068cbc(5,5,u_MaxLength_000799b0,(short *)puVar1[0xc]);
    FUN_0005fd58((longlong *)&local_res8);
  }
  pwVar12 = (wchar_t *)puVar1[7];
  if ((pwVar12 == (wchar_t *)0x0) || (pwVar15 = pwVar12, *pwVar12 == L'\0')) {
LAB_0005f5bc:
    if (puVar1[3] == 0) {
      pwVar12 = u_Not_configurable_as_no_attribute_0007fe40;
      goto LAB_0005f5c9;
    }
  }
  else {
    do {
      pwVar15 = pwVar15 + 1;
      ppsVar8 = (short **)((longlong)ppsVar8 + 1);
    } while (*pwVar15 != L'\0');
    if (ppsVar8 == (short **)0x0) goto LAB_0005f5bc;
LAB_0005f5c9:
    local_res8 = FUN_00068cbc(4,5,u_WarningText_000794b0,pwVar12);
    FUN_0005fd58((longlong *)&local_res8);
  }
  if ((short *)*puVar1 != (short *)0x0) {
    if (*(int *)((longlong)puVar1 + 0x24) - 10U < 2) {
      iVar13 = 5;
    }
    local_res8 = FUN_00068cbc(iVar13,5,u_DefaultValue_00079ab0,(short *)*puVar1);
    FUN_0005fd58((longlong *)&local_res8);
  }
  pwVar15 = (wchar_t *)0x0;
  pwVar12 = (wchar_t *)0x0;
  iVar13 = 1;
LAB_0005f640:
  local_res8 = FUN_00068cbc(iVar13,lVar11,pwVar12,pwVar15);
  FUN_0005fd58((longlong *)&local_res8);
  return;
}

