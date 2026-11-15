
ulonglong * Observed_PageInput(longlong param_1,ulonglong *param_2,ulonglong *param_3)

{
  bool bVar1;
  ushort uVar2;
  short sVar3;
  uint uVar4;
  longlong lVar5;
  undefined8 uVar6;
  ulonglong uVar8;
  longlong lVar9;
  longlong *plVar10;
  short *psVar11;
  int *piVar12;
  ulonglong *puVar13;
  longlong *plVar14;
  uint uVar15;
  ulonglong *puVar17;
  longlong lVar18;
  ulonglong *puVar19;
  ulonglong local_res10;
  ulonglong local_res18;
  ulonglong *local_res20;
  undefined8 local_58;
  undefined8 uStack_50;
  undefined4 local_48;
  ulonglong *puVar7;
  ulonglong *puVar16;
  
  puVar16 = (ulonglong *)0x0;
  local_res18._0_2_ = 0;
  lVar18 = -0x7ffffffffffffffd;
  puVar17 = (ulonglong *)0x8000000000000003;
  local_res20 = (ulonglong *)0x8000000000000003;
  uVar15 = *(uint *)(DAT_000afdd0 + 0x28);
  uVar2 = 0;
  if (((short)param_2[1] == 1) && (*(short *)((longlong)param_2 + 0xc) == 0x16)) {
    puVar13 = &local_res10;
    local_res10 = 0;
    lVar5 = FUN_00018c00((uint)*(ushort *)(param_1 + 0x30),(longlong *)puVar13);
    if (-1 < lVar5) {
      uVar2 = *(ushort *)(local_res10 + 0xe);
    }
    if (uVar2 == 0xffff) {
      DAT_000afe48 = (short *)0x0;
    }
    else {
      param_3 = (ulonglong *)0x0;
      puVar13 = (ulonglong *)(ulonglong)uVar2;
      DAT_000afe48 = (short *)FUN_0004bc70(*(longlong *)(param_1 + 0x20),uVar2,(short *)0x0);
      if (DAT_000afe48 != (short *)0x0) {
        sVar3 = *DAT_000afe48;
        psVar11 = DAT_000afe48;
        puVar7 = puVar16;
        puVar19 = puVar16;
        while (sVar3 != 0) {
          uVar2 = *(short *)((longlong)puVar19 + (longlong)psVar11) - 0x22;
          if (((uVar2 < 0x3b) &&
              (param_3 = (ulonglong *)0x400000035002101,
              (0x400000035002101U >> ((ulonglong)uVar2 & 0x3f) & 1) != 0)) ||
             (*(short *)((longlong)puVar19 + (longlong)psVar11) == 0x7c)) {
            *(undefined2 *)((longlong)puVar19 + (longlong)psVar11) = 0x2d;
            psVar11 = DAT_000afe48;
          }
          puVar7 = (ulonglong *)(ulonglong)((int)puVar7 + 1);
          puVar13 = (ulonglong *)((longlong)puVar7 * 2);
          puVar19 = puVar13;
          sVar3 = *(short *)((longlong)puVar13 + (longlong)psVar11);
        }
      }
    }
    local_res20 = (ulonglong *)0x8000000000000003;
    goto LAB_000239cb;
  }
  puVar7 = puVar16;
  piVar12 = (int *)PTR_DAT_00094670;
  puVar19 = puVar16;
  if (*(int *)(param_1 + 0x4c) != 0) {
LAB_00023a8d:
    do {
      if (*piVar12 != (int)puVar19) {
        uVar4 = (int)puVar7 + 1;
        puVar7 = (ulonglong *)(ulonglong)uVar4;
        piVar12 = piVar12 + 6;
        if (uVar4 < 6) goto LAB_00023a8d;
      }
      puVar13 = param_2;
      lVar5 = (*(code *)PTR_Observed_FrameInput_00093da8)
                        (*(undefined8 *)(*(longlong *)(param_1 + 0x50) + (longlong)puVar7 * 8));
      if (lVar5 == 0) goto LAB_00023b05;
      uVar4 = (int)puVar19 + 1;
      puVar19 = (ulonglong *)(ulonglong)uVar4;
      puVar7 = puVar16;
      piVar12 = (int *)PTR_DAT_00094670;
    } while (uVar4 < *(uint *)(param_1 + 0x4c));
  }
  puVar13 = &local_res10;
  local_res10 = 0;
  lVar5 = FUN_00018c00((uint)*(ushort *)(param_1 + 0x30),(longlong *)puVar13);
  if ((-1 < lVar5) && ((*(uint *)(local_res10 + 0x14) >> 4 & 1) != 0)) {
    local_res20 = (ulonglong *)0x8000000000000003;
    if ((short)param_2[1] == 1) {
      *(undefined2 *)(param_2 + 1) = 0;
    }
    goto LAB_000239cb;
  }
  puVar7 = puVar16;
  if (*(int *)(param_1 + 0x58) != 0) {
    do {
      puVar13 = param_2;
      lVar5 = (*(code *)PTR_FUN_00093ec0)
                        (*(undefined8 *)(*(longlong *)(param_1 + 0x60) + (longlong)puVar7 * 8));
      if (lVar5 == 0) goto LAB_00023b05;
      uVar4 = (int)puVar7 + 1;
      puVar7 = (ulonglong *)(ulonglong)uVar4;
    } while (uVar4 < *(uint *)(param_1 + 0x58));
  }
  sVar3 = (short)param_2[1];
  if (sVar3 == 1) {
    local_58 = *(undefined8 *)((longlong)param_2 + 0xc);
    uStack_50 = *(undefined8 *)((longlong)param_2 + 0x14);
    local_48 = *(undefined4 *)((longlong)param_2 + 0x1c);
    uVar8 = FUN_0000ff10(&local_58);
    if ((int)uVar8 != 0xd) {
      sVar3 = (short)param_2[1];
      goto LAB_00023b6c;
    }
  }
  else {
LAB_00023b6c:
    if ((sVar3 != 3) || (uVar8 = FUN_000103c4((longlong)param_2 + 0xc), (int)uVar8 != 0xd))
    goto LAB_000239cb;
  }
  lVar5 = DAT_000afdd0;
  if (*(short *)(param_1 + 0x32) == 0) {
    param_3 = &local_res10;
    puVar13 = &local_res18;
    local_res20 = (ulonglong *)
                  Observed_HistoryLookup
                            (*(ushort *)(DAT_000afdd0 + 0x28),(undefined2 *)puVar13,(uint *)param_3)
    ;
    puVar17 = local_res20;
    if (local_res20 == (ulonglong *)0x0) {
      *(uint *)(lVar5 + 0x28) = (uint)(ushort)local_res18;
    }
  }
  else if (*(ushort *)(param_1 + 0x30) != *(ushort *)(param_1 + 0x32)) {
    uVar6 = FUN_000495f4((ulonglong)DAT_000baaf0[(ulonglong)*(ushort *)(param_1 + 0x30) + 1] +
                         DAT_000babc0);
    puVar17 = puVar16;
    piVar12 = (int *)PTR_DAT_00094670;
    if ((char)uVar6 != '\x01') {
      do {
        uVar4 = (uint)puVar17;
        if (*piVar12 == 0) break;
        uVar4 = uVar4 + 1;
        puVar17 = (ulonglong *)(ulonglong)uVar4;
        piVar12 = piVar12 + 6;
      } while (uVar4 < 6);
      lVar5 = *(longlong *)(*(longlong *)(param_1 + 0x50) + (ulonglong)uVar4 * 8);
      puVar17 = puVar16;
      if (*(int *)(lVar5 + 0x3c) != 0) {
        do {
          bVar1 = FUN_00022d54(lVar5,(uint)puVar17);
          if (bVar1) {
            *(undefined4 *)(lVar5 + 0x5c) = 0;
            break;
          }
          uVar4 = (uint)puVar17 + 1;
          puVar17 = (ulonglong *)(ulonglong)uVar4;
        } while (uVar4 < *(uint *)(lVar5 + 0x3c));
      }
      lVar5 = DAT_000afdd0;
      param_3 = &local_res10;
      puVar13 = &local_res18;
      lVar9 = Observed_HistoryLookup
                        (*(ushort *)(DAT_000afdd0 + 0x28),(undefined2 *)puVar13,(uint *)param_3);
      uVar2 = (ushort)local_res18;
      if (lVar9 != 0) {
        uVar2 = *(ushort *)(param_1 + 0x32);
      }
      *(uint *)(lVar5 + 0x28) = (uint)uVar2;
      *(undefined1 *)(DAT_000afdd0 + 0x58) = 1;
      *(undefined4 *)(DAT_000afdd0 + 0x5c) = 2;
    }
    local_res20 = (ulonglong *)0x0;
    puVar17 = puVar16;
  }
LAB_000239cb:
  if ((DAT_000aff20 != '\0') &&
     (lVar5 = param_1, uVar6 = FUN_0001b784(param_1), (char)uVar6 == '\0')) {
    DAT_000aff21 = 1;
    puVar17 = (ulonglong *)Candidate_PendingUpdate(lVar5,puVar13,param_3);
    DAT_000aff21 = 0;
    local_res20 = puVar17;
  }
  if ((uVar15 == *(uint *)(DAT_000afdd0 + 0x28)) ||
     (lVar5 = FUN_00010594((ulonglong)
                           *(uint *)(DAT_000baae8 + 4 +
                                    (ulonglong)
                                    *(ushort *)
                                     ((ulonglong)DAT_000baaf0[(ulonglong)uVar15 + 1] + DAT_000babc0
                                     + 8) * 4) + DAT_000baae8,
                           (ulonglong)DAT_000baaf0[(ulonglong)uVar15 + 1] + DAT_000babc0 + 10,
                           (ulonglong)
                           *(uint *)(DAT_000baae8 + 4 +
                                    (ulonglong)
                                    *(ushort *)
                                     ((ulonglong)
                                      DAT_000baaf0[(ulonglong)*(uint *)(DAT_000afdd0 + 0x28) + 1] +
                                      DAT_000babc0 + 8) * 4) + DAT_000baae8,
                           (ulonglong)DAT_000baaf0[(ulonglong)*(uint *)(DAT_000afdd0 + 0x28) + 1] +
                           DAT_000babc0 + 10), lVar5 != -0x7ffffffffffffff1)) {
    if (puVar17 == (ulonglong *)0x0) {
      Observed_HistoryUpdate(*(ushort *)(param_1 + 0x30),*(ushort *)(DAT_000afdd0 + 0x28));
    }
    if ((((DAT_000afe58 != 0) && (uVar4 = *(uint *)(DAT_000afdd0 + 0x28), uVar15 != uVar4)) &&
        (uVar4 != 0)) &&
       ((*(longlong *)((ulonglong)DAT_000baaf0[(ulonglong)uVar15 + 1] + DAT_000babc0) !=
         *(longlong *)((ulonglong)DAT_000baaf0[(ulonglong)uVar4 + 1] + DAT_000babc0) &&
        (lVar5 = (**(code **)(DAT_000afc38 + 0x50))(DAT_000afc38,DAT_000afe58,&local_res18),
        -1 < lVar5)))) {
      (**(code **)(DAT_000afbc8 + 0x110))(CONCAT62(local_res18._2_6_,(ushort)local_res18),0,0);
      (**(code **)(DAT_000afbc8 + 0x108))(CONCAT62(local_res18._2_6_,(ushort)local_res18),0,0,1);
      DAT_000afe58 = 0;
    }
    if (uVar15 != *(uint *)(DAT_000afdd0 + 0x28)) {
      sVar3 = *(short *)(DAT_000afdd0 + 0x28);
      local_res10 = local_res10 & 0xffffffff00000000;
      DAT_000afd88 = 1;
      if ((DAT_000babc0 != 0) && (*DAT_000baaf0 != 0)) {
        do {
          puVar17 = local_res20;
          if (lVar18 == 0) break;
          plVar14 = (longlong *)((ulonglong)DAT_000baaf0[(longlong)puVar16 + 1] + DAT_000babc0);
          if ((((plVar14 != (longlong *)0x0) && (*plVar14 != 0)) && (*plVar14 != 0xffff)) &&
             ((short)plVar14[2] == sVar3)) {
            plVar10 = FUN_00059b50(puVar16,0x28);
            (**(code **)(DAT_000afbc8 + 0x160))(plVar10,plVar14,0x28);
            while (lVar18 = FUN_0003f414((longlong)plVar14,3,(uint *)&local_res10),
                  lVar18 == -0x7ffffffffffffffa) {
              plVar14 = FUN_0003f578(plVar10);
            }
            local_res10 = local_res10 & 0xffffffff00000000;
            if (plVar10 != (longlong *)0x0) {
              (**(code **)(DAT_000afbc8 + 0x48))(plVar10);
            }
          }
          uVar15 = (int)puVar16 + 1;
          puVar16 = (ulonglong *)(ulonglong)uVar15;
          puVar17 = local_res20;
        } while (uVar15 < *DAT_000baaf0);
      }
      DAT_000afd88 = 0;
      FUN_00049d50(*(uint *)(DAT_000afdd0 + 0x28));
    }
  }
  else {
    *(uint *)(DAT_000afdd0 + 0x28) = uVar15;
  }
  return puVar17;
LAB_00023b05:
  local_res20 = (ulonglong *)0x0;
  puVar17 = puVar16;
  goto LAB_000239cb;
}

