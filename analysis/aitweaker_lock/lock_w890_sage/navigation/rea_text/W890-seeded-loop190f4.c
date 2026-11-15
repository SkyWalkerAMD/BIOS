
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* WARNING: Enum "SectionFlags": Some values do not have unique names */

void Observed_BrowserLoop(void)

{
  char cVar1;
  ushort uVar2;
  bool bVar3;
  uint uVar4;
  longlong lVar5;
  word *pwVar6;
  ulonglong uVar7;
  longlong lVar8;
  undefined8 *puVar9;
  undefined8 uVar10;
  word *pwVar11;
  longlong lVar12;
  dword *pdVar13;
  longlong *plVar14;
  int iVar15;
  word *pwVar16;
  ulonglong uVar17;
  uint uVar18;
  uint uVar19;
  ulonglong local_res8;
  ushort local_res10 [4];
  undefined2 local_res18 [4];
  word *local_res20;
  int local_a8 [2];
  undefined8 local_a0;
  undefined8 local_98;
  longlong local_90;
  undefined1 local_88 [16];
  undefined8 local_78;
  undefined8 uStack_70;
  undefined4 local_68;
  undefined8 local_58;
  undefined8 local_50;
  
  pwVar11 = (word *)0x0;
  local_res10[0] = 0;
  local_res8 = local_res8 & 0xffffffffffff0000;
  bVar3 = true;
  local_res18[0] = 0;
  uVar18 = 1;
  local_58 = 0;
  local_50 = 0;
  (**(code **)(DAT_000afbc8 + 0x140))(&DAT_00093388,0,&local_90);
  _DAT_000afcb0 = 4;
  pwVar16 = (word *)&DAT_00093cd8;
  pdVar13 = (dword *)&DAT_000baab8;
  (**(code **)(DAT_000afbc8 + 0x148))(&DAT_000baab8,&DAT_00093cd8,&PTR_LAB_00093ce8,0);
  DAT_000afce1 = 0;
  FUN_0004e53c();
  if (DAT_000afdf0 == '\0') {
    local_res20 = (word *)0x0;
    pwVar16 = &IMAGE_DOS_HEADER_00000000.e_cparhdr;
    local_a0 = 0;
    pdVar13 = &IMAGE_SECTION_HEADER_000001f0.SizeOfRawData;
    local_78 = 0x43372b4cd3431c06;
    uStack_70 = 0x211555c0d9ff3493;
    lVar5 = (**(code **)(DAT_000afbc8 + 0x50))(0x200,8,&LAB_0001bb44,0,&local_res20);
    if (-1 < lVar5) {
      pdVar13 = (dword *)&local_78;
      pwVar16 = local_res20;
      (**(code **)(DAT_000afbc8 + 0xa8))();
    }
    DAT_000afdf0 = '\x01';
  }
  DAT_00093a68 = 0x1f;
  DAT_00093a70 = 100;
  FUN_00011278();
  if ((DAT_000baa68 == 0) && (pwVar6 = pwVar11, DAT_000afdd0 != 0)) {
LAB_0001924e:
    FUN_0001793c();
  }
  else {
    pwVar6 = (word *)FUN_00018e1c(pdVar13,(ulonglong)pwVar16);
    if ((longlong)pwVar6 < 0) goto LAB_00019a76;
    if (DAT_000baa68 == 0) goto LAB_0001924e;
  }
  if ((DAT_000afcc0 != (undefined8 *)0x0) &&
     ((*(code *)*DAT_000afcc0)(DAT_000afcc0,local_a8,0,0), local_a8[0] == 1)) {
    (*(code *)DAT_000afcc0[1])(DAT_000afcc0,0);
  }
  FUN_00049ec0();
  FUN_00010e8c(0x1f);
  FUN_0000fd18(0xffff0022,FUN_0004f634);
  if (DAT_000babf0 != (undefined1 *)0x0) {
    FUN_00001600(DAT_000babf0,0xb71b04,0);
  }
  if (((DAT_000baa68 != 0) || (DAT_000afdd0 == 0)) &&
     ((pwVar6 = (word *)(*(code *)PTR_FUN_00093cf0)(&DAT_000afdd0), (longlong)pwVar6 < 0 ||
      (pwVar6 = (word *)(*(code *)PTR_FUN_00093d00)(DAT_000afdd0,DAT_000babc0), (longlong)pwVar6 < 0
      )))) goto LAB_00019a76;
  FUN_0000fd18(0xffff002a,&LAB_000069ec);
  DAT_000baa90 = *(undefined8 *)(DAT_000afdd0 + 0x20);
  pwVar16 = pwVar11;
  if (*DAT_000baaf8 != 0) {
    do {
      uVar19 = (uint)pwVar16;
      if (((uVar19 < *DAT_000baaf8) &&
          ((ulonglong)DAT_000baaf8[(longlong)((longlong)pwVar16 + 1)] + (longlong)DAT_000baaf8 != 0)
          ) && (*(int *)((ulonglong)DAT_000baaf8[(longlong)((longlong)pwVar16 + 1)] +
                         (longlong)DAT_000baaf8 + 100) == 0xf017)) {
        FUN_0001ccbc(uVar19,0,2,local_res10);
        break;
      }
      pwVar16 = (word *)(ulonglong)(uVar19 + 1);
    } while (uVar19 + 1 < *DAT_000baaf8);
  }
  lVar5 = *(longlong *)(DAT_000afdd0 + 0x20);
  if (*(longlong *)(DAT_000afdd0 + 0x30) == 0) {
    *(undefined1 *)(DAT_000afdd0 + 0x5a) = 1;
  }
  else {
    if (DAT_000afdc4 != 0) {
      uVar7 = FUN_00018ff4();
      DAT_000afdc4 = (int)uVar7;
    }
    iVar15 = DAT_000afdc4;
    *(int *)(DAT_000afdd0 + 0x28) = DAT_000afdc4;
    if (iVar15 == 0) {
      if (((DAT_000baa68 == 0) || (lVar8 = FUN_000387dc((undefined2 *)&local_res8), lVar8 != 0)) ||
         ((ushort)local_res8 == 0xffff)) {
        *(undefined4 *)(DAT_000afdd0 + 0x28) = 1;
      }
      else {
        *(uint *)(DAT_000afdd0 + 0x28) = (uint)(ushort)local_res8;
      }
    }
    lVar8 = *(longlong *)(DAT_000afdd0 + 0x30);
    lVar12 = *(longlong *)(lVar8 + (ulonglong)*(uint *)(DAT_000afdd0 + 0x28) * 8);
    if ((lVar12 != 0) && ((*(byte *)(lVar12 + 0x34) & 1) == 0)) goto LAB_00019463;
    uVar19 = *(uint *)(DAT_000afdd0 + 0x2c);
    pwVar16 = pwVar11;
    if (uVar19 != 0) {
      do {
        iVar15 = (int)pwVar16;
        lVar12 = *(longlong *)(lVar8 + (longlong)pwVar16 * 8);
        if ((((lVar12 != 0) && (*(short *)(lVar12 + 0x30) != 0)) && (*(short *)(lVar12 + 0x32) == 0)
            ) && ((*(byte *)(lVar12 + 0x34) & 1) == 0)) goto LAB_00019459;
        pwVar16 = (word *)(ulonglong)(iVar15 + 1U);
        pwVar6 = pwVar11;
      } while (iVar15 + 1U < uVar19);
      do {
        iVar15 = (int)pwVar6;
        lVar12 = *(longlong *)(lVar8 + (longlong)pwVar6 * 8);
        if ((lVar12 != 0) && ((*(byte *)(lVar12 + 0x34) & 1) == 0)) goto LAB_00019459;
        pwVar6 = (word *)(ulonglong)(iVar15 + 1U);
      } while (iVar15 + 1U < uVar19);
    }
    pwVar6 = (word *)0x800000000000000e;
  }
LAB_00019994:
  FUN_0000fd18(0xffff002b,&LAB_000069ec);
  (**(code **)(DAT_000afbc8 + 0x150))(DAT_000baab8,&DAT_00093cd8,&PTR_LAB_00093ce8,0);
  DAT_000baab8 = 0;
  if ((DAT_000afdc8 != '\0') && (DAT_000baa68 == 0)) {
    FUN_0000748c(pwVar6);
    FUN_0000fd18(0xffff001e,&LAB_000069ec);
    local_res8 = 0;
    pwVar6 = (word *)(**(code **)(DAT_000afbc8 + 0x140))(&DAT_000938b8,0,&local_res8);
    if (-1 < (longlong)pwVar6) {
      (**(code **)(DAT_000afbd8 + 0x68))(0,0,0,0);
    }
    (**(code **)(DAT_000afbd8 + 0x68))(1,0,0,0);
  }
  if (DAT_000afde8 != (undefined8 *)0x0) {
    (**(code **)(DAT_000afbc8 + 0x48))();
    DAT_000afde8 = (undefined8 *)0x0;
  }
  DAT_000afe00 = 0;
  DAT_000afddc = 0;
LAB_00019a76:
  FUN_0000748c(pwVar6);
  return;
LAB_00019459:
  *(int *)(DAT_000afdd0 + 0x28) = iVar15;
LAB_00019463:
  uVar19 = *(uint *)(DAT_000afdd0 + 0x28);
  FUN_00010648(1,0x3050006);
  local_res20 = (word *)CONCAT44(local_res20._4_4_,0xffffffff);
  _DAT_000afcb0 = 5;
  local_res8 = local_res8 & 0xffffffffffff0000;
  uVar2 = *(ushort *)(DAT_000afdd0 + 0x28);
  uVar7 = (ulonglong)uVar2;
  if (uVar2 != 0) {
    uVar4 = DAT_000afddc;
    if (DAT_000afde8 == (undefined8 *)0x0) {
      lVar8 = *(longlong *)(*(longlong *)(DAT_000afdd0 + 0x30) + uVar7 * 8);
      if (*(short *)(lVar8 + 0x32) == 0) {
        DAT_000afde0 = *(int *)(DAT_000afdd0 + 0x2c) + 0x14;
        DAT_000afde8 = FUN_00059b50(lVar8,(ulonglong)DAT_000afde0 << 5);
        uVar4 = (uint)uVar2;
        if (DAT_000afde8 != (undefined8 *)0x0) goto LAB_000194ed;
      }
    }
    else {
LAB_000194ed:
      DAT_000afddc = uVar4;
      puVar9 = DAT_000afde8;
      lVar8 = Observed_HistoryLookup(uVar2,(undefined2 *)&local_res8,(uint *)&local_res20);
      if (lVar8 != -0x7fffffffffffffeb) {
        if (lVar8 == 0) {
          if ((uint)local_res20 < DAT_000afde0) {
            DAT_000afe00 = (uint)local_res20 + 1;
            if ((DAT_000afe00 < DAT_000afde0) &&
               (uVar7 = (ulonglong)(DAT_000afde0 - DAT_000afe00), uVar7 != 0)) {
              puVar9 = puVar9 + (ulonglong)DAT_000afe00 * 4;
LAB_0001954d:
              FUN_00001600((undefined1 *)puVar9,uVar7 << 5,0);
            }
          }
          else {
LAB_0001958c:
            if (DAT_000afde0 <= DAT_000afe00) {
              uVar4 = DAT_000afde0 + 0x14;
              uVar17 = (ulonglong)DAT_000afde0;
              DAT_000afde0 = uVar4;
              puVar9 = FUN_0000fc40((longlong)puVar9,uVar17,(ulonglong)uVar4);
              DAT_000afde8 = puVar9;
              if (puVar9 == (undefined8 *)0x0) {
                DAT_000afe00 = 0;
                goto LAB_0001964f;
              }
            }
            lVar8 = *(longlong *)(*(longlong *)(DAT_000afdd0 + 0x30) + uVar7 * 8);
            if (lVar8 != 0) {
              uVar17 = (ulonglong)DAT_000afe00;
              puVar9[uVar17 * 4] = *(undefined8 *)(lVar8 + 0x20);
              *(uint *)(DAT_000afde8 + uVar17 * 4 + 1) =
                   (uint)*(ushort *)
                          (*(longlong *)(*(longlong *)(DAT_000afdd0 + 0x30) + uVar7 * 8) + 0x2a);
              if (DAT_000afe00 != 0) {
                DAT_000afde8[uVar17 * 4 + 2] = DAT_000afde8[(ulonglong)(DAT_000afe00 - 1) * 4];
                *(undefined4 *)(DAT_000afde8 + uVar17 * 4 + 3) =
                     *(undefined4 *)(DAT_000afde8 + (ulonglong)(DAT_000afe00 - 1) * 4 + 1);
              }
              DAT_000afe00 = DAT_000afe00 + 1;
            }
          }
        }
        else {
          if ((DAT_000afde0 <= (uint)local_res20) || ((ushort)local_res8 != 0)) goto LAB_0001958c;
          DAT_000afe00 = 1;
          if ((1 < DAT_000afde0) && (uVar7 = (ulonglong)(DAT_000afde0 - 1), uVar7 != 0)) {
            puVar9 = puVar9 + 4;
            goto LAB_0001954d;
          }
        }
      }
    }
  }
LAB_0001964f:
  lVar8 = (ulonglong)*(uint *)(DAT_000baaf0 + 4 + (ulonglong)*(uint *)(DAT_000afdd0 + 0x28) * 4) +
          DAT_000babc0;
  FUN_00010594(&local_58,local_res18,
               (ulonglong)*(uint *)(DAT_000baae8 + 4 + (ulonglong)*(ushort *)(lVar8 + 8) * 4) +
               DAT_000baae8,lVar8 + 10);
  lVar8 = (**(code **)(DAT_000afbc8 + 0x50))(0x200,8,FUN_00007650,0,&local_98);
  if (lVar8 < 0) {
    return;
  }
  pwVar6 = (word *)(**(code **)(DAT_000afbc8 + 0xa8))(&DAT_00093588,local_98,local_88);
  if ((longlong)pwVar6 < 0) {
    return;
  }
  cVar1 = *(char *)(DAT_000afdd0 + 0x5a);
  while (local_res20 = pwVar6, cVar1 == '\0') {
    FUN_0004cd14();
    uVar4 = *(uint *)(DAT_000afdd0 + 0x28);
    if (uVar19 == uVar4) {
      if (*(char *)(DAT_000afdd0 + 0x58) != '\0') {
        FUN_00064b2c(uVar18);
      }
    }
    else {
      lVar8 = *(longlong *)(*(longlong *)(DAT_000afdd0 + 0x30) + (ulonglong)uVar4 * 8);
      if ((lVar8 == 0) || (*(longlong *)(lVar8 + 0x20) == 0)) {
        *(uint *)(DAT_000afdd0 + 0x28) = uVar19;
        uVar4 = uVar19;
      }
      else {
        plVar14 = (longlong *)
                  ((ulonglong)*(uint *)(DAT_000baaf0 + 4 + (ulonglong)uVar19 * 4) + DAT_000babc0);
        if (*plVar14 != 0) {
          uVar10 = FUN_000495f4((longlong)plVar14);
          if ((char)uVar10 == '\0') {
            uVar4 = *(uint *)(DAT_000afdd0 + 0x28);
          }
          else {
            *(uint *)(DAT_000afdd0 + 0x28) = uVar19;
            uVar4 = uVar19;
          }
        }
      }
      uVar19 = uVar4;
      if ((uVar18 != 1) && (uVar4 != uVar18)) {
        FUN_00064b2c(uVar18);
        *(undefined1 *)(DAT_000afdd0 + 0x58) = 1;
      }
    }
    lVar8 = *(longlong *)(*(longlong *)(DAT_000afdd0 + 0x30) + (ulonglong)uVar19 * 8);
    if (*(short *)(lVar5 + 8) != 0) {
      (*(code *)PTR_FUN_00093dd8)(lVar5);
    }
    if ((*(char *)(DAT_000afdd0 + 0x58) != '\0') || (bVar3)) {
      if (pwVar11 != (word *)0x0) {
        (**(code **)(DAT_000afbc8 + 0x48))(pwVar11);
      }
      local_res8 = 0;
      pwVar11 = (word *)FUN_0001d5d4(1,&local_res8);
      if ((pwVar11 != (word *)0x0) && (local_res8 < 0x28)) {
        (**(code **)(DAT_000afbc8 + 0x168))(&DAT_000ba920,0x28,0);
        (**(code **)(DAT_000afbc8 + 0x160))(&DAT_000ba920,pwVar11);
      }
      if (*(char *)(DAT_000afdd0 + 0x59) != '\0') {
        *(undefined1 *)(DAT_000afdd0 + 0x58) = 1;
        if (DAT_000babf0 != (undefined1 *)0x0) {
          FUN_00001600(DAT_000babf0,0xb71b04,0);
        }
        FUN_00010e8c(0x1f);
        *(undefined1 *)(DAT_000afdd0 + 0x59) = 0;
      }
      if (*(char *)(DAT_000afdd0 + 0x58) == '\0') {
        (*(code *)PTR_FUN_00093df8)(lVar8);
      }
      else {
        FUN_0004a08c(uVar19);
        FUN_00064d1c(uVar19);
        (*(code *)PTR_FUN_00093df8)(lVar8);
        *(undefined1 *)(DAT_000afdd0 + 0x58) = 0;
      }
      FUN_000113d4();
      uVar18 = uVar19;
    }
    bVar3 = false;
    lVar12 = (*(code *)PTR_FUN_00093dd0)(lVar5);
    if (lVar12 == 0) {
      lVar12 = (*(code *)PTR_Observed_PageInput_00093e00)(lVar8,lVar5);
      if (lVar12 == 0) {
LAB_0001994d:
        bVar3 = true;
      }
      else {
        if (*(short *)(lVar5 + 8) == 1) {
          local_78 = *(undefined8 *)(lVar5 + 0xc);
          uStack_70 = *(undefined8 *)(lVar5 + 0x14);
          local_68 = *(undefined4 *)(lVar5 + 0x1c);
          uVar7 = FUN_0000ff10(&local_78);
          if (((int)uVar7 != 0xd) && ((*(byte *)(lVar8 + 0x34) & 4) != 0)) {
            (*(code *)PTR_FUN_00093dd8)(lVar5);
            goto LAB_0001995f;
          }
        }
        lVar8 = (*(code *)PTR_FUN_00093d10)(DAT_000afdd0,lVar5);
        if (lVar8 == 0) goto LAB_0001994d;
        if (*(short *)(lVar5 + 8) == 1) {
          FUN_0000fd18(0xffff0016,&LAB_000069ec);
        }
      }
      if (local_90 != 0) {
        (**(code **)(local_90 + 0x24))();
      }
    }
LAB_0001995f:
    pwVar6 = local_res20;
    cVar1 = *(char *)(DAT_000afdd0 + 0x5a);
  }
  FUN_00064b2c(*(uint *)(DAT_000afdd0 + 0x28));
  if (pwVar11 != (word *)0x0) {
    (**(code **)(DAT_000afbc8 + 0x48))(pwVar11);
  }
  goto LAB_00019994;
}

