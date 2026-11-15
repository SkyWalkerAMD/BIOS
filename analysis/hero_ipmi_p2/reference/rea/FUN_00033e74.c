
ulonglong FUN_00033e74(ulonglong param_1)

{
  short sVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  ulonglong uVar6;
  char cVar7;
  longlong *plVar8;
  undefined8 uVar9;
  longlong lVar10;
  ulonglong *puVar11;
  longlong lVar12;
  ulonglong *puVar13;
  ulonglong uVar14;
  ulonglong uVar15;
  ulonglong *puVar16;
  ulonglong uVar17;
  ulonglong uVar18;
  ulonglong uVar19;
  char local_res10;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  longlong local_48 [2];
  
  uVar14 = 0;
  local_68 = 0xf22fc20c;
  bVar3 = false;
  uVar19 = 0x800000000000000e;
  bVar5 = false;
  local_64 = 0x45eb8cf4;
  bVar2 = true;
  local_60 = 0x4ead068e;
  local_res10 = '\x01';
  local_5c = 0xd35db950;
  local_58 = 0x337f4407;
  local_54 = 0x4b835aee;
  local_50 = 0xad4ea7b2;
  local_4c = 0xcd8830ca;
  if (DAT_0018f190 == 0) {
    return 0x800000000000000e;
  }
  uVar18 = uVar14;
  puVar11 = DAT_0018f1a0;
  uVar17 = uVar14;
  uVar15 = DAT_0018f188;
  if (*DAT_001937e8 != 0) {
    do {
      puVar11 = (ulonglong *)((ulonglong)DAT_001937e8[uVar18 + 1] + DAT_001938e0);
      if (*puVar11 == param_1) {
        bVar4 = !bVar3;
        bVar3 = bVar5;
        if (bVar4) {
          lVar10 = (ulonglong)*(uint *)(DAT_001937b0 + 4 + (ulonglong)(ushort)puVar11[1] * 4) +
                   DAT_001937b0;
          if (lVar10 != 0) {
            (**(code **)(DAT_00180188 + 0x160))(local_48,lVar10,0x10);
            uVar14 = 0;
          }
          bVar3 = true;
        }
        if ((uint)uVar14 < *(uint *)((longlong)puVar11 + 0x1c)) {
          puVar13 = puVar11 + 4;
          uVar19 = uVar14;
          do {
            puVar16 = (ulonglong *)((ulonglong)(uint)*puVar13 + DAT_001937f8);
            if ((*(uint *)((longlong)puVar16 + 0x1c) & 0x10000) != 0) {
              FUN_000359ac((longlong *)puVar16);
              uVar14 = 0;
            }
            *puVar16 = uVar14;
            uVar19 = uVar19 + 1;
            puVar13 = (ulonglong *)((longlong)puVar13 + 4);
          } while (uVar19 < *(uint *)((longlong)puVar11 + 0x1c));
        }
        if ((((*(byte *)((longlong)puVar11 + 0x14) & 0x80) != 0) &&
            (DAT_0018f138 != (ulonglong *)0x0)) &&
           (puVar13 = DAT_0018f138, uVar19 = uVar14, (ulonglong)DAT_0018f130 != 0)) {
          do {
            if (((*puVar13 != uVar14) && (puVar16 = (ulonglong *)puVar13[1], *puVar11 == *puVar16))
               && (((short)puVar11[2] == (short)puVar16[2] &&
                   ((short)puVar11[1] == (short)puVar16[1])))) {
              lVar10 = (**(code **)(DAT_00180188 + 0x70))(DAT_0018f138[uVar19 * 2]);
              uVar14 = 0;
              if (lVar10 == 0) {
                DAT_0018f138[uVar19 * 2] = 0;
              }
              break;
            }
            uVar19 = uVar19 + 1;
            puVar13 = puVar13 + 2;
          } while (uVar19 < DAT_0018f130);
        }
        sVar1 = *(short *)((longlong)puVar11 + 10);
        uVar19 = *puVar11;
        cVar7 = (char)uVar14;
        if ((*(byte *)((longlong)puVar11 + 0x14) & 0x20) == 0) {
          cVar7 = local_res10;
        }
        plVar8 = FUN_00067d50((short)uVar18);
        if (((plVar8 != (longlong *)0x0) &&
            (sVar1 == *(short *)((longlong)*(ulonglong **)(*plVar8 + 0x10) + 10))) &&
           (**(ulonglong **)(*plVar8 + 0x10) == uVar19)) {
          DAT_00190b48 = FUN_00001450(DAT_00190b48,DAT_00190b30 * 8,DAT_00190b30 * 8 + 8);
          lVar10 = DAT_00190b30;
          DAT_00190b30 = DAT_00190b30 + 1;
          uVar14 = 0;
          *(longlong **)(DAT_00190b48 + lVar10 * 8) = plVar8;
        }
        if (DAT_0013bba4 == uVar18) {
          DAT_00190b38 = 1;
          DAT_00190b2c = sVar1;
          DAT_00190b40 = uVar19;
        }
        *puVar11 = 0xffff;
        uVar19 = uVar14;
        local_res10 = cVar7;
        bVar5 = bVar3;
      }
      uVar6 = DAT_0018f188;
      uVar18 = uVar18 + 1;
    } while (uVar18 < *DAT_001937e8);
    uVar18 = uVar14;
    puVar11 = DAT_0018f1a0;
    uVar17 = uVar14;
    uVar15 = DAT_0018f188;
    if ((bVar3) && (plVar8 = DAT_0018f198, uVar15 = uVar14, DAT_0018f188 != 0)) {
      do {
        lVar10 = FUN_000b1b20(plVar8,local_48,0x10);
        uVar18 = 0;
        puVar11 = DAT_0018f1a0;
        uVar17 = uVar18;
        uVar15 = uVar14;
        if (lVar10 == 0) break;
        uVar14 = uVar14 + 1;
        plVar8 = plVar8 + 2;
        uVar15 = uVar14;
      } while (uVar14 < uVar6);
    }
  }
  while( true ) {
    puVar13 = DAT_0018f1a0;
    if (DAT_0018f190 <= uVar18) {
      return uVar19;
    }
    if ((puVar11[1] == param_1) && (*puVar11 != uVar17)) break;
    uVar18 = uVar18 + 1;
    puVar11 = puVar11 + 6;
  }
  uVar14 = DAT_0018f1a0[uVar18 * 6];
  lVar12 = uVar14 + 4;
  lVar10 = FUN_000b1b20((longlong *)(uVar14 + 6),(longlong *)&local_68,0x10);
  if (lVar10 != 0) {
    if (lVar12 == 0) {
      cVar7 = '\0';
    }
    else {
      uVar9 = FUN_00031b40(lVar12,(longlong *)&local_68);
      cVar7 = (char)uVar9;
    }
    if ((cVar7 == '\0') &&
       (lVar10 = FUN_000b1b20((longlong *)(uVar14 + 6),(longlong *)&local_58,0x10), lVar10 != 0)) {
      if (lVar12 == 0) {
        cVar7 = '\0';
      }
      else {
        uVar9 = FUN_00031b40(lVar12,(longlong *)&local_58);
        cVar7 = (char)uVar9;
      }
      if (cVar7 == '\0') {
        bVar2 = false;
      }
    }
  }
  *(undefined2 *)(puVar13 + uVar18 * 6 + 2) = 0;
  DAT_0018f1a0[uVar18 * 6 + 3] = 0;
  *(undefined1 *)(DAT_0018f1a0 + uVar18 * 6 + 4) = 0;
  *(undefined2 *)(uVar18 * 0x30 + 0x22 + (longlong)DAT_0018f1a0) = 0;
  FUN_000013d0((longlong *)(DAT_0018f1a0 + uVar18 * 6));
  if (bVar2) {
    return uVar19;
  }
  if (local_res10 != '\0') {
    return uVar19;
  }
  if (uVar15 != DAT_0018f188) {
    return uVar19;
  }
  FUN_0003644c();
  return uVar19;
}

