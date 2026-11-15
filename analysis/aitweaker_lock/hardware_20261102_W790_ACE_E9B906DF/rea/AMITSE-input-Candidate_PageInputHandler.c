
ulonglong Candidate_PageInputHandler(longlong **param_1,longlong **param_2,uint *param_3)

{
  longlong **pplVar1;
  byte bVar2;
  bool bVar3;
  ushort uVar4;
  uint uVar5;
  longlong **pplVar6;
  ulonglong uVar7;
  longlong **pplVar8;
  longlong lVar9;
  undefined8 uVar10;
  longlong lVar11;
  longlong *plVar12;
  int *piVar13;
  longlong **pplVar14;
  ulonglong uVar15;
  uint uVar16;
  longlong *plVar18;
  uint *puVar19;
  int iVar20;
  longlong lVar21;
  short sVar22;
  longlong *local_res10;
  uint local_res18 [2];
  longlong **local_res20;
  longlong *local_68 [2];
  longlong *local_58;
  undefined8 uStack_50;
  undefined4 local_48;
  longlong **pplVar17;
  
  pplVar17 = (longlong **)0x0;
  local_res10 = (longlong *)((ulonglong)local_res10 & 0xffffffffffff0000);
  lVar21 = -0x7ffffffffffffffd;
  uVar15 = 0x8000000000000003;
  uVar16 = *(uint *)(DAT_00082748 + 0x28);
  iVar20 = 1;
  uVar4 = 0;
  pplVar14 = (longlong **)0x8000000000000006;
  if ((*(short *)(param_2 + 1) == 1) && (*(short *)((longlong)param_2 + 0xc) == 0x16)) {
    local_res10 = (longlong *)0x0;
    if (DAT_00092b08 != 0) {
      uVar4 = 0;
      iVar20 = 1;
      pplVar14 = (longlong **)FUN_0000dd70((uint)*(ushort *)(param_1 + 6),(longlong *)&local_res10);
    }
    if (-1 < (longlong)pplVar14) {
      uVar4 = *(ushort *)((longlong)local_res10 + 0xe);
    }
    pplVar6 = pplVar17;
    if (uVar4 != 0xffff) {
      param_3 = (uint *)0x0;
      pplVar14 = (longlong **)(ulonglong)uVar4;
      pplVar6 = (longlong **)FUN_00033df4((longlong)param_1[4],uVar4,(short *)0x0);
      iVar20 = 1;
    }
    DAT_000827c0 = pplVar6;
    if (pplVar6 != (longlong **)0x0) {
      sVar22 = *(short *)pplVar6;
      pplVar8 = pplVar17;
      pplVar1 = pplVar17;
      while (sVar22 != 0) {
        uVar4 = *(short *)((longlong)pplVar1 + (longlong)pplVar6) - 0x22;
        if (((uVar4 < 0x3b) &&
            (param_3 = (uint *)0x400000035002101,
            (0x400000035002101U >> ((ulonglong)uVar4 & 0x3f) & 1) != 0)) ||
           (*(short *)((longlong)pplVar1 + (longlong)pplVar6) == 0x7c)) {
          *(undefined2 *)((longlong)pplVar1 + (longlong)pplVar6) = 0x2d;
          pplVar6 = DAT_000827c0;
        }
        pplVar8 = (longlong **)(ulonglong)(uint)((int)pplVar8 + iVar20);
        pplVar14 = (longlong **)((longlong)pplVar8 * 2);
        pplVar1 = pplVar14;
        sVar22 = *(short *)((longlong)pplVar14 + (longlong)pplVar6);
      }
    }
    goto LAB_00016f9b;
  }
  pplVar6 = pplVar17;
  piVar13 = (int *)PTR_DAT_0006b7f0;
  pplVar8 = pplVar17;
  if (*(int *)((longlong)param_1 + 0x4c) != 0) {
LAB_00016dac:
    do {
      if (*piVar13 != (int)pplVar8) {
        uVar5 = (int)pplVar6 + 1;
        pplVar6 = (longlong **)(ulonglong)uVar5;
        piVar13 = piVar13 + 6;
        if (uVar5 < 6) goto LAB_00016dac;
      }
      pplVar6 = (longlong **)param_1[10][(longlong)pplVar6];
      pplVar14 = param_2;
      lVar11 = (*(code *)PTR_FUN_0006af28)();
      if (lVar11 == 0) goto LAB_00016f98;
      uVar5 = (int)pplVar8 + 1;
      pplVar8 = (longlong **)(ulonglong)uVar5;
      pplVar6 = pplVar17;
      piVar13 = (int *)PTR_DAT_0006b7f0;
    } while (uVar5 < *(uint *)((longlong)param_1 + 0x4c));
  }
  sVar22 = 1;
  pplVar6 = (longlong **)(ulonglong)*(ushort *)(param_1 + 6);
  bVar2 = FUN_0000ddbc((uint)*(ushort *)(param_1 + 6));
  if (bVar2 != 0) {
    if (*(short *)(param_2 + 1) == sVar22) {
      *(undefined2 *)(param_2 + 1) = 0;
    }
    goto LAB_00016f9b;
  }
  pplVar8 = pplVar17;
  if (*(int *)(param_1 + 0xb) != 0) {
    do {
      pplVar6 = (longlong **)param_1[0xc][(longlong)pplVar8];
      pplVar14 = param_2;
      lVar11 = (*(code *)PTR_FUN_0006b040)();
      if (lVar11 == 0) goto LAB_00016f98;
      sVar22 = 1;
      uVar5 = (int)pplVar8 + 1;
      pplVar8 = (longlong **)(ulonglong)uVar5;
    } while (uVar5 < *(uint *)(param_1 + 0xb));
  }
  if (*(short *)(param_2 + 1) == sVar22) {
    local_58 = *(longlong **)((longlong)param_2 + 0xc);
    uStack_50 = *(undefined8 *)((longlong)param_2 + 0x14);
    local_48 = *(undefined4 *)((longlong)param_2 + 0x1c);
    pplVar6 = &local_58;
    uVar7 = FUN_00005cb0(pplVar6);
    if ((int)uVar7 != 0xd) goto LAB_00016e60;
  }
  else {
LAB_00016e60:
    if (*(short *)(param_2 + 1) != 3) goto LAB_00016f9b;
    pplVar6 = (longlong **)((longlong)param_2 + 0xc);
    uVar7 = FUN_000060ec((longlong)pplVar6);
    if ((int)uVar7 != 0xd) goto LAB_00016f9b;
  }
  lVar11 = DAT_00082748;
  if (*(short *)((longlong)param_1 + 0x32) == 0) {
    pplVar6 = (longlong **)(ulonglong)*(ushort *)(DAT_00082748 + 0x28);
    if (*(longlong *)(*(longlong *)(DAT_00082748 + 0x30) + (longlong)pplVar6 * 8) == 0) {
      uVar15 = 0x8000000000000015;
    }
    else {
      pplVar6 = (longlong **)(ulonglong)*(ushort *)(DAT_00082748 + 0x28);
      param_3 = local_res18;
      pplVar14 = &local_res10;
      uVar15 = FUN_0001017c(*(ushort *)(DAT_00082748 + 0x28),(undefined2 *)pplVar14,(int *)param_3);
      if (uVar15 == 0) {
        pplVar6 = (longlong **)((ulonglong)local_res10 & 0xffff);
        *(uint *)(lVar11 + 0x28) = (uint)(ushort)local_res10;
      }
    }
    goto LAB_00016f9b;
  }
  if (*(ushort *)(param_1 + 6) == *(ushort *)((longlong)param_1 + 0x32)) goto LAB_00016f9b;
  pplVar6 = (longlong **)
            ((ulonglong)DAT_00092270[(ulonglong)*(ushort *)(param_1 + 6) + 1] + DAT_00092b08);
  uVar10 = FUN_000322b4((longlong)pplVar6);
  pplVar8 = pplVar17;
  piVar13 = (int *)PTR_DAT_0006b7f0;
  if ((char)uVar10 != '\x01') {
    do {
      uVar5 = (uint)pplVar8;
      if (*piVar13 == 0) break;
      uVar5 = uVar5 + 1;
      pplVar8 = (longlong **)(ulonglong)uVar5;
      piVar13 = piVar13 + 6;
    } while (uVar5 < 6);
    lVar11 = param_1[10][uVar5];
    pplVar6 = pplVar17;
    if (*(int *)(lVar11 + 0x3c) != 0) {
      do {
        pplVar14 = pplVar6;
        uVar5 = (uint)pplVar14;
        bVar3 = FUN_00016178(lVar11,uVar5);
        if (bVar3) {
          *(undefined4 *)(lVar11 + 0x5c) = 0;
          break;
        }
        uVar5 = uVar5 + 1;
        pplVar6 = (longlong **)(ulonglong)uVar5;
      } while (uVar5 < *(uint *)(lVar11 + 0x3c));
    }
    lVar11 = DAT_00082748;
    pplVar6 = (longlong **)(ulonglong)*(ushort *)(DAT_00082748 + 0x28);
    if (*(longlong *)(*(longlong *)(DAT_00082748 + 0x30) + (longlong)pplVar6 * 8) == 0) {
LAB_00016f78:
      uVar4 = *(ushort *)((longlong)param_1 + 0x32);
    }
    else {
      param_3 = local_res18;
      pplVar14 = &local_res10;
      lVar9 = FUN_0001017c(*(ushort *)(DAT_00082748 + 0x28),(undefined2 *)pplVar14,(int *)param_3);
      uVar4 = (ushort)local_res10;
      if (lVar9 != 0) goto LAB_00016f78;
    }
    *(uint *)(lVar11 + 0x28) = (uint)uVar4;
    *(undefined1 *)(DAT_00082748 + 0x58) = 1;
    *(undefined4 *)(DAT_00082748 + 0x5c) = 2;
  }
LAB_00016f98:
  uVar15 = 0;
LAB_00016f9b:
  if ((DAT_00082898 != '\0') &&
     (pplVar6 = param_1, uVar10 = FUN_000100ec((longlong)param_1), (char)uVar10 == '\0')) {
    DAT_00082899 = 1;
    uVar15 = FUN_00029b34(pplVar6,pplVar14,param_3);
    DAT_00082899 = 0;
  }
  if (uVar16 != *(uint *)(DAT_00082748 + 0x28)) {
    lVar11 = FUN_000062bc((ulonglong)
                          *(uint *)(DAT_00092268 + 4 +
                                   (ulonglong)
                                   *(ushort *)
                                    ((ulonglong)DAT_00092270[(ulonglong)uVar16 + 1] + 8 +
                                    DAT_00092b08) * 4) + DAT_00092268,
                          DAT_00092b08 + 10 + (ulonglong)DAT_00092270[(ulonglong)uVar16 + 1],
                          (ulonglong)
                          *(uint *)(DAT_00092268 + 4 +
                                   (ulonglong)
                                   *(ushort *)
                                    ((ulonglong)
                                     DAT_00092270[(ulonglong)*(uint *)(DAT_00082748 + 0x28) + 1] +
                                     DAT_00092b08 + 8) * 4) + DAT_00092268,
                          (ulonglong)DAT_00092270[(ulonglong)*(uint *)(DAT_00082748 + 0x28) + 1] +
                          DAT_00092b08 + 10);
    pplVar6 = (longlong **)0x800000000000000f;
    if (lVar11 == -0x7ffffffffffffff1) {
      *(uint *)(DAT_00082748 + 0x28) = uVar16;
      return uVar15;
    }
  }
  if (uVar15 == 0) {
    pplVar6 = (longlong **)(ulonglong)*(ushort *)(param_1 + 6);
    FUN_00010270(*(ushort *)(param_1 + 6),*(ushort *)(DAT_00082748 + 0x28));
  }
  if (DAT_000827d0 != 0) {
    uVar5 = *(uint *)(DAT_00082748 + 0x28);
    pplVar14 = (longlong **)(ulonglong)uVar5;
    pplVar6 = pplVar14;
    if (((uVar16 != uVar5) && (uVar5 != 0)) &&
       ((pplVar6 = (longlong **)(ulonglong)DAT_00092270[(ulonglong)uVar16 + 1],
        *(longlong *)((longlong)(ulonglong)DAT_00092270[(ulonglong)uVar16 + 1] + DAT_00092b08) !=
        *(longlong *)((ulonglong)DAT_00092270[(longlong)pplVar14 + 1] + DAT_00092b08) &&
        (pplVar6 = DAT_000825d8,
        lVar11 = (*(code *)DAT_000825d8[10])(DAT_000825d8,DAT_000827d0,&local_res20), -1 < lVar11)))
       ) {
      (**(code **)(DAT_000824c8 + 0x110))(local_res20,0,0);
      (**(code **)(DAT_000824c8 + 0x108))(local_res20,0,0,1);
      DAT_000827d0 = 0;
      pplVar6 = local_res20;
    }
  }
  if (uVar16 != *(uint *)(DAT_00082748 + 0x28)) {
    sVar22 = *(short *)(DAT_00082748 + 0x28);
    local_res10 = (longlong *)CONCAT62(local_res10._2_6_,sVar22);
    local_res18[0] = 0;
    DAT_00082700 = 1;
    if ((DAT_00092b08 != 0) && (puVar19 = DAT_00092270, *DAT_00092270 != 0)) {
      do {
        if (lVar21 == 0) break;
        plVar18 = (longlong *)((ulonglong)puVar19[(longlong)pplVar17 + 1] + DAT_00092b08);
        if ((((plVar18 != (longlong *)0x0) && (*plVar18 != 0)) && (*plVar18 != 0xffff)) &&
           ((short)plVar18[2] == sVar22)) {
          plVar12 = FUN_0003eea8(pplVar6,0x28);
          local_68[0] = plVar12;
          (**(code **)(DAT_000824c8 + 0x160))(plVar12,plVar18,0x28);
          while (lVar21 = FUN_00029070((longlong)plVar18,3,local_res18),
                lVar21 == -0x7ffffffffffffffa) {
            plVar18 = FUN_000291d4(plVar12);
          }
          pplVar6 = local_68;
          local_res18[0] = 0;
          FUN_00005958((longlong *)pplVar6);
          puVar19 = DAT_00092270;
          sVar22 = (ushort)local_res10;
        }
        uVar16 = (int)pplVar17 + 1;
        pplVar17 = (longlong **)(ulonglong)uVar16;
      } while (uVar16 < *puVar19);
    }
    DAT_00082700 = 0;
    FUN_000329cc(*(uint *)(DAT_00082748 + 0x28));
  }
  return uVar15;
}

