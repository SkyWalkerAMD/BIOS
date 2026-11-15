
/* WARNING: Enum "SectionFlags": Some values do not have unique names */

void FUN_0000e1b8(void)

{
  char cVar1;
  longlong lVar2;
  ulonglong uVar3;
  longlong lVar4;
  undefined8 uVar5;
  char *pcVar6;
  longlong lVar7;
  Misc *pMVar8;
  longlong *plVar9;
  int iVar10;
  undefined *puVar11;
  char *pcVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  char *pcVar16;
  ulonglong local_res8;
  ushort local_res10 [4];
  undefined2 local_res18 [4];
  int local_res20 [2];
  char *local_98;
  undefined *local_90;
  undefined8 local_88;
  undefined8 *local_78;
  undefined8 uStack_70;
  undefined4 local_68;
  undefined8 local_58;
  undefined8 local_50;
  
  pcVar6 = (char *)0x0;
  DAT_00083468 = 4;
  local_res10[0] = 0;
  local_98 = (char *)0x0;
  puVar11 = &DAT_0006b808;
  local_res8 = local_res8 & 0xffffffffffff0000;
  pMVar8 = (Misc *)&DAT_00093078;
  local_res18[0] = 0;
  pcVar16 = IMAGE_DOS_HEADER_00000000.e_magic + 1;
  local_58 = 0;
  uVar13 = 1;
  local_50 = 0;
  uVar15 = 0;
  (**(code **)(DAT_00083308 + 0x148))(&DAT_00093078,&DAT_0006b808,&PTR_FUN_0006b818,0);
  DAT_00083499 = 0;
  FUN_00036140();
  if (DAT_000835a8 == '\0') {
    local_90 = (undefined *)0x0;
    puVar11 = (undefined *)0x8;
    local_88 = 0;
    pMVar8 = &IMAGE_SECTION_HEADER_000001f8.Misc;
    local_78 = (undefined8 *)0x43372b4cd3431c06;
    uStack_70 = 0x211555c0d9ff3493;
    lVar2 = (**(code **)(DAT_00083308 + 0x50))(0x200,8,&LAB_00010460,0,&local_90);
    if (-1 < lVar2) {
      pMVar8 = (Misc *)&local_78;
      puVar11 = local_90;
      (**(code **)(DAT_00083308 + 0xa8))();
    }
    DAT_000835a8 = '\x01';
  }
  DAT_0006b598 = 0x1f;
  DAT_0006b5a0 = 100;
  FUN_00006eb0((undefined8 *)pMVar8);
  if ((DAT_00093028 == 0) && (DAT_00083588 != 0)) {
    local_90 = (undefined *)0x0;
LAB_0000e307:
    puVar11 = local_90;
    FUN_0000cd68();
  }
  else {
    puVar11 = (undefined *)FUN_0000def0((undefined8 **)pMVar8,(ulonglong)puVar11);
    local_90 = puVar11;
    if ((longlong)puVar11 < 0) goto LAB_0000e619;
    if (DAT_00093028 == 0) goto LAB_0000e307;
  }
  if ((DAT_00083478 != (undefined8 *)0x0) &&
     ((*(code *)*DAT_00083478)(DAT_00083478,local_res20,0,0), local_res20[0] == 1)) {
    (*(code *)DAT_00083478[1])(DAT_00083478,0);
  }
  FUN_00032af0();
  FUN_00006be8(0x1f);
  FUN_00005a68(0xffff0022,&LAB_00036dfc);
  if (DAT_00093978 != (undefined8 *)0x0) {
    FUN_00000360(DAT_00093978,0xb71b04,0);
  }
  if (((DAT_00093028 != 0) || (DAT_00083588 == 0)) &&
     ((puVar11 = (undefined *)(*(code *)PTR_FUN_0006b820)(&DAT_00083588), (longlong)puVar11 < 0 ||
      (puVar11 = (undefined *)(*(code *)PTR_FUN_0006b830)(DAT_00083588,DAT_00093948),
      local_90 = puVar11, (longlong)puVar11 < 0)))) goto LAB_0000e619;
  FUN_00005a68(0xffff002a,&LAB_00006320);
  DAT_00093050 = *(undefined8 *)(DAT_00083588 + 0x20);
  if (*DAT_000930b8 != 0) {
    pcVar12 = pcVar6;
    if (*DAT_000930b8 == 0) goto LAB_0000e40a;
    do {
      uVar15 = (uint)pcVar12;
      pcVar12 = (char *)((ulonglong)DAT_000930b8[(longlong)(pcVar12 + 1)] + (longlong)DAT_000930b8);
      if ((pcVar12 != (char *)0x0) && (*(int *)(pcVar12 + 100) == 0xf017)) goto LAB_0000e419;
LAB_0000e40a:
      pcVar12 = (char *)(ulonglong)(uVar15 + 1);
    } while (uVar15 + 1 < *DAT_000930b8);
  }
  pcVar12 = pcVar6;
  uVar15 = (uint)local_res8;
LAB_0000e419:
  if (pcVar12 != (char *)0x0) {
    FUN_000114c8(uVar15,0,2,local_res10);
  }
  lVar2 = *(longlong *)(DAT_00083588 + 0x20);
  if (*(longlong *)(DAT_00083588 + 0x30) == 0) {
    *(undefined1 *)(DAT_00083588 + 0x5a) = 1;
  }
  else {
    if (DAT_0008357c != 0) {
      uVar3 = FUN_0000e0b8();
      DAT_0008357c = (int)uVar3;
    }
    iVar10 = DAT_0008357c;
    *(int *)(DAT_00083588 + 0x28) = DAT_0008357c;
    if (iVar10 == 0) {
      if (((DAT_00093028 == 0) || (lVar4 = FUN_00022898((undefined2 *)&local_res8), lVar4 != 0)) ||
         ((ushort)local_res8 == 0xffff)) {
        *(undefined4 *)(DAT_00083588 + 0x28) = 1;
      }
      else {
        *(uint *)(DAT_00083588 + 0x28) = (uint)(ushort)local_res8;
      }
    }
    lVar4 = *(longlong *)(DAT_00083588 + 0x30);
    lVar7 = *(longlong *)(lVar4 + (ulonglong)*(uint *)(DAT_00083588 + 0x28) * 8);
    if ((lVar7 != 0) && ((*(byte *)(lVar7 + 0x34) & 1) == 0)) goto LAB_0000e63c;
    uVar15 = *(uint *)(DAT_00083588 + 0x2c);
    pcVar12 = pcVar6;
    if (uVar15 != 0) {
      do {
        iVar10 = (int)pcVar12;
        lVar7 = *(longlong *)(lVar4 + (longlong)pcVar12 * 8);
        if (((lVar7 != 0) && (*(short *)(lVar7 + 0x30) != 0)) &&
           ((*(short *)(lVar7 + 0x32) == 0 && ((*(byte *)(lVar7 + 0x34) & 1) == 0))))
        goto LAB_0000e632;
        pcVar12 = (char *)(ulonglong)(iVar10 + 1U);
      } while (iVar10 + 1U < uVar15);
    }
    pcVar12 = pcVar6;
    if (uVar15 != 0) {
      do {
        iVar10 = (int)pcVar12;
        lVar7 = *(longlong *)(lVar4 + (longlong)pcVar12 * 8);
        if ((lVar7 != 0) && ((*(byte *)(lVar7 + 0x34) & 1) == 0)) goto LAB_0000e632;
        pcVar12 = (char *)(ulonglong)(iVar10 + 1U);
      } while (iVar10 + 1U < uVar15);
    }
    puVar11 = (undefined *)0x800000000000000e;
  }
LAB_0000e52d:
  FUN_00005908((longlong *)&local_98);
  FUN_00005a68(0xffff002b,&LAB_00006320);
  (**(code **)(DAT_00083308 + 0x150))(DAT_00093078,&DAT_0006b808,&PTR_FUN_0006b818,0);
  DAT_00093078 = 0;
  if ((DAT_00083580 != '\0') && (DAT_00093028 == 0)) {
    FUN_0000122c(puVar11);
    FUN_00005a68(0xffff001e,&LAB_00006320);
    local_res8 = 0;
    puVar11 = (undefined *)(**(code **)(DAT_00083308 + 0x140))(&DAT_0006b410,0,&local_res8);
    if (-1 < (longlong)puVar11) {
      (**(code **)(DAT_00083318 + 0x68))(0,0,0,0);
    }
    (**(code **)(DAT_00083318 + 0x68))(0,0,0,0);
  }
  if (DAT_000835a0 != 0) {
    FUN_00005908(&DAT_000835a0);
    DAT_000835a0 = 0;
  }
  DAT_000835b8 = 0;
  DAT_00083594 = 0;
LAB_0000e619:
  FUN_0000122c(puVar11);
  return;
LAB_0000e632:
  *(int *)(DAT_00083588 + 0x28) = iVar10;
LAB_0000e63c:
  uVar15 = *(uint *)(DAT_00083588 + 0x28);
  FUN_000063d8(1,0x3050006);
  DAT_00083468 = 5;
  FUN_00010220(0,*(ushort *)(DAT_00083588 + 0x28));
  lVar4 = (ulonglong)*(uint *)(DAT_000930b0 + 4 + (ulonglong)*(uint *)(DAT_00083588 + 0x28) * 4) +
          DAT_00093948;
  FUN_0000626c(&local_58,local_res18,
               (ulonglong)*(uint *)(DAT_000930a8 + 4 + (ulonglong)*(ushort *)(lVar4 + 8) * 4) +
               DAT_000930a8,lVar4 + 10);
  cVar1 = *(char *)(DAT_00083588 + 0x5a);
  while (cVar1 == '\0') {
    FUN_00034b2c();
    uVar14 = *(uint *)(DAT_00083588 + 0x28);
    if (uVar15 == uVar14) {
      if (*(char *)(DAT_00083588 + 0x58) != '\0') {
        FUN_00049e5c(uVar13);
      }
    }
    else {
      lVar4 = *(longlong *)(*(longlong *)(DAT_00083588 + 0x30) + (ulonglong)uVar14 * 8);
      if ((lVar4 == 0) || (*(longlong *)(lVar4 + 0x20) == 0)) {
        *(uint *)(DAT_00083588 + 0x28) = uVar15;
        uVar14 = uVar15;
      }
      else {
        plVar9 = (longlong *)
                 ((ulonglong)*(uint *)(DAT_000930b0 + 4 + (ulonglong)uVar15 * 4) + DAT_00093948);
        if (*plVar9 != 0) {
          uVar5 = FUN_00032264((longlong)plVar9);
          if ((char)uVar5 == '\0') {
            uVar14 = *(uint *)(DAT_00083588 + 0x28);
          }
          else {
            *(uint *)(DAT_00083588 + 0x28) = uVar15;
            uVar14 = uVar15;
          }
        }
      }
      uVar15 = uVar14;
      if ((uVar13 != 1) && (uVar14 != uVar13)) {
        FUN_00049e5c(uVar13);
        *(undefined1 *)(DAT_00083588 + 0x58) = 1;
      }
    }
    lVar4 = *(longlong *)(*(longlong *)(DAT_00083588 + 0x30) + (ulonglong)uVar15 * 8);
    if (*(short *)(lVar2 + 8) != 0) {
      (*(code *)PTR_FUN_0006b908)();
    }
    if (*(char *)(DAT_00083588 + 0x58) != '\0') {
      pcVar16 = IMAGE_DOS_HEADER_00000000.e_magic + 1;
    }
    if ((char)pcVar16 != '\0') {
      pcVar16 = (char *)0x0;
      if (pcVar6 != (char *)0x0) {
        FUN_00005908((longlong *)&local_98);
      }
      local_res8 = 0;
      if (*DAT_000930b8 < 2) {
        local_98 = (char *)0x0;
        pcVar6 = pcVar16;
      }
      else {
        pcVar6 = (char *)FUN_00011d7c(1,&local_res8);
        local_98 = pcVar6;
        if ((pcVar6 != (char *)0x0) && (local_res8 < 0x28)) {
          (**(code **)(DAT_00083308 + 0x168))(&DAT_00092ee0,0x28);
          (**(code **)(DAT_00083308 + 0x160))(&DAT_00092ee0,pcVar6);
        }
      }
      if (*(char *)(DAT_00083588 + 0x59) != '\0') {
        *(undefined1 *)(DAT_00083588 + 0x58) = 1;
        if (DAT_00093978 != (undefined8 *)0x0) {
          FUN_00000360(DAT_00093978,0xb71b04,0);
        }
        FUN_00006be8(0x1f);
        *(undefined1 *)(DAT_00083588 + 0x59) = 0;
      }
      if (*(char *)(DAT_00083588 + 0x58) == '\0') {
        (*(code *)PTR_FUN_0006b928)(lVar4);
      }
      else {
        FUN_00032ce0(uVar15);
        FUN_00049ff4(uVar15);
        (*(code *)PTR_FUN_0006b928)(lVar4);
        *(undefined1 *)(DAT_00083588 + 0x58) = 0;
      }
      FUN_00006ffc();
      uVar13 = uVar15;
    }
    lVar7 = (*(code *)PTR_FUN_0006b900)(lVar2);
    if (lVar7 == 0) {
      lVar7 = (*(code *)PTR_FUN_0006b930)(lVar4,lVar2);
      if (lVar7 == 0) {
        pcVar16 = IMAGE_DOS_HEADER_00000000.e_magic + 1;
      }
      else {
        if (*(short *)(lVar2 + 8) == 1) {
          local_78 = *(undefined8 **)(lVar2 + 0xc);
          uStack_70 = *(undefined8 *)(lVar2 + 0x14);
          local_68 = *(undefined4 *)(lVar2 + 0x1c);
          uVar3 = FUN_00005c60(&local_78);
          if (((int)uVar3 != 0xd) && ((*(byte *)(lVar4 + 0x34) & 4) != 0)) {
            (*(code *)PTR_FUN_0006b908)(lVar2);
            goto LAB_0000e91e;
          }
        }
        lVar4 = (*(code *)PTR_FUN_0006b840)(DAT_00083588,lVar2);
        if (lVar4 == 0) {
          pcVar16 = IMAGE_DOS_HEADER_00000000.e_magic + 1;
        }
        else if (*(short *)(lVar2 + 8) == 1) {
          FUN_00005a68(0xffff0016,&LAB_00006320);
        }
      }
    }
LAB_0000e91e:
    puVar11 = local_90;
    cVar1 = *(char *)(DAT_00083588 + 0x5a);
  }
  FUN_00049e5c(*(uint *)(DAT_00083588 + 0x28));
  goto LAB_0000e52d;
}

