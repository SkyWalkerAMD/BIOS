
void Candidate_FormOpenCallbacks(uint param_1)

{
  char *pcVar1;
  short sVar2;
  int *piVar3;
  longlong lVar4;
  ushort uVar5;
  longlong lVar6;
  ushort uVar7;
  longlong lVar8;
  uint uVar9;
  uint uVar10;
  undefined8 *puVar11;
  longlong *plVar12;
  ulonglong uVar13;
  longlong *plVar14;
  uint *puVar15;
  ulonglong uVar16;
  ulonglong uVar17;
  undefined4 uVar18;
  ulonglong uVar19;
  int iVar20;
  char local_res8 [8];
  uint local_res10;
  undefined8 local_res18;
  
  uVar13 = 0;
  local_res8[0] = '\x01';
  piVar3 = (int *)PTR_DAT_0006b7f0;
  uVar17 = uVar13;
  do {
    if (*piVar3 == 0) break;
    uVar9 = (int)uVar17 + 1;
    uVar17 = (ulonglong)uVar9;
    piVar3 = piVar3 + 6;
  } while (uVar9 < 6);
  uVar19 = (ulonglong)param_1;
  plVar14 = (longlong *)((ulonglong)*(uint *)(DAT_00092270 + 4 + uVar19 * 4) + DAT_00092b08);
  if (*plVar14 == 0) {
    return;
  }
  if (*plVar14 == 0xffff) {
    return;
  }
  uVar7 = 0;
  uVar5 = uVar7;
  if (*(int *)((longlong)plVar14 + 0x1c) != 0) {
    do {
      sVar2 = FUN_0001e86c((longlong *)
                           ((ulonglong)*(uint *)((longlong)plVar14 + (ulonglong)uVar5 * 4 + 0x20) +
                           DAT_00092288),&local_res18);
      if (sVar2 != -2) {
        lVar6 = *(longlong *)
                 (*(longlong *)
                   (*(longlong *)(*(longlong *)(DAT_00082748 + 0x30) + uVar19 * 8) + 0x50) +
                 (uVar17 & 0xffff) * 8);
        iVar20 = *(int *)(lVar6 + 0x3c);
        uVar9 = *(uint *)(lVar6 + 0x44);
        puVar11 = *(undefined8 **)(lVar6 + 0x48);
        uVar18 = *(undefined4 *)(lVar6 + 0x5c);
        local_res10 = uVar9;
        if (iVar20 != 0) {
          do {
            (**(code **)(*(longlong *)*puVar11 + 8))((longlong *)*puVar11,1);
            uVar7 = uVar7 + 1;
            puVar11 = puVar11 + 1;
          } while ((uint)uVar7 < *(uint *)(lVar6 + 0x3c));
        }
        *(undefined8 *)(lVar6 + 0x3c) = 0;
        uVar5 = 0;
        *(undefined4 *)(lVar6 + 0x44) = 0;
        *(undefined4 *)(lVar6 + 0x5c) = 0;
        if (*(int *)((longlong)plVar14 + 0x1c) != 0) {
          do {
            plVar12 = (longlong *)
                      ((ulonglong)*(uint *)((longlong)plVar14 + (ulonglong)uVar5 * 4 + 0x20) +
                      DAT_00092288);
            if ((((plVar12 != (longlong *)0x0) && ((*(byte *)((longlong)plVar12 + 0x1c) & 1) != 0))
                && (sVar2 = FUN_00048ee8(lVar6,plVar12,local_res8), sVar2 != -1)) &&
               (lVar8 = FUN_00047d5c(lVar6,plVar12,local_res8), lVar8 == 0)) {
              FUN_00048f4c(*(longlong *)
                            (*(longlong *)(lVar6 + 0x48) +
                            (ulonglong)(*(int *)(lVar6 + 0x3c) - 1) * 8));
            }
            uVar5 = uVar5 + 1;
            uVar9 = local_res10;
          } while ((uint)uVar5 < *(uint *)((longlong)plVar14 + 0x1c));
        }
        goto LAB_00049a78;
      }
      uVar5 = uVar5 + 1;
    } while ((uint)uVar5 < *(uint *)((longlong)plVar14 + 0x1c));
  }
  lVar8 = (ulonglong)*(uint *)(DAT_00092270 + 4 + uVar19 * 4) + DAT_00092b08;
  if ((ulonglong)*(uint *)(lVar8 + 0x1c) == 0) {
    return;
  }
  puVar15 = (uint *)(lVar8 + 0x20);
  uVar17 = uVar13;
  while ((((plVar14 = (longlong *)((ulonglong)*puVar15 + DAT_00092288), plVar14 == (longlong *)0x0
           || (*plVar14 == 0)) ||
          ((pcVar1 = (char *)plVar14[5], pcVar1 == (char *)0x0 || (*pcVar1 != '\x0f')))) ||
         ((piVar3 = (int *)PTR_DAT_0006b7f0, uVar16 = uVar13, (pcVar1[1] & 0x7fU) != 0xd &&
          ((pcVar1[1] & 0x7fU) < 0x21))))) {
    uVar17 = uVar17 + 1;
    puVar15 = puVar15 + 1;
    if (*(uint *)(lVar8 + 0x1c) <= uVar17) {
      return;
    }
  }
  do {
    if (*piVar3 == 0) break;
    uVar9 = (int)uVar16 + 1;
    uVar16 = (ulonglong)uVar9;
    piVar3 = piVar3 + 6;
  } while (uVar9 < 6);
  local_res8[0] = '\x01';
  lVar6 = *(longlong *)
           (*(longlong *)(*(longlong *)(*(longlong *)(DAT_00082748 + 0x30) + uVar19 * 8) + 0x50) +
           (uVar16 & 0xffff) * 8);
  iVar20 = *(int *)(lVar6 + 0x3c);
  puVar11 = *(undefined8 **)(lVar6 + 0x48);
  uVar9 = *(uint *)(lVar6 + 0x44);
  uVar18 = *(undefined4 *)(lVar6 + 0x5c);
  uVar17 = uVar13;
  if (iVar20 != 0) {
    do {
      (**(code **)(*(longlong *)*puVar11 + 8))((longlong *)*puVar11,1);
      puVar11 = puVar11 + 1;
      uVar10 = (int)uVar17 + 1;
      uVar17 = (ulonglong)uVar10;
    } while (uVar10 < *(uint *)(lVar6 + 0x3c));
  }
  *(undefined8 *)(lVar6 + 0x3c) = 0;
  *(undefined4 *)(lVar6 + 0x44) = 0;
  *(undefined4 *)(lVar6 + 0x5c) = 0;
  if (*(int *)(lVar8 + 0x1c) != 0) {
    do {
      plVar14 = (longlong *)((ulonglong)*(uint *)(lVar8 + 0x20 + uVar13 * 4) + DAT_00092288);
      if ((((plVar14 != (longlong *)0x0) && ((*(byte *)((longlong)plVar14 + 0x1c) & 1) != 0)) &&
          (sVar2 = FUN_00048ee8(lVar6,plVar14,local_res8), sVar2 != -1)) &&
         (lVar4 = FUN_00047d5c(lVar6,plVar14,local_res8), lVar4 == 0)) {
        FUN_00048f4c(*(longlong *)
                      (*(longlong *)(lVar6 + 0x48) + (ulonglong)(*(int *)(lVar6 + 0x3c) - 1) * 8));
      }
      uVar10 = (int)uVar13 + 1;
      uVar13 = (ulonglong)uVar10;
    } while (uVar10 < *(uint *)(lVar8 + 0x1c));
  }
LAB_00049a78:
  if (*(int *)(lVar6 + 0x3c) == iVar20) {
    *(uint *)(lVar6 + 0x44) = uVar9;
    *(undefined4 *)(lVar6 + 0x5c) = uVar18;
    FUN_00016178(lVar6,uVar9);
  }
  return;
}

