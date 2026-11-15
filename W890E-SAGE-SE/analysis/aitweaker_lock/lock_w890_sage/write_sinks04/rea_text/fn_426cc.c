
undefined8 FUN_000426cc(longlong param_1)

{
  longlong *plVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  bool bVar6;
  longlong lVar7;
  longlong *plVar8;
  ulonglong uVar9;
  undefined8 uVar10;
  uint *puVar11;
  longlong *plVar12;
  bool bVar13;
  ulonglong uVar14;
  ulonglong uVar15;
  longlong local_38;
  longlong local_30;
  
  uVar15 = 0;
  uVar10 = 0x800000000000000e;
  bVar13 = false;
  bVar2 = true;
  bVar3 = true;
  if (DAT_000aff68 != 0) {
    uVar14 = DAT_000aff60;
    bVar4 = bVar3;
    bVar6 = true;
    if (*DAT_000baaf0 != 0) {
      do {
        plVar8 = (longlong *)((ulonglong)DAT_000baaf0[uVar15 + 1] + DAT_000babc0);
        bVar5 = bVar6;
        if (*plVar8 == param_1) {
          if ((!bVar13) &&
             (lVar7 = (ulonglong)
                      *(uint *)(DAT_000baae8 + 4 + (ulonglong)*(ushort *)(plVar8 + 1) * 4) +
                      DAT_000baae8, bVar13 = bVar3, lVar7 != 0)) {
            (**(code **)(DAT_000afbc8 + 0x160))(&local_38,lVar7,0x10);
          }
          uVar14 = 0;
          if (*(int *)((longlong)plVar8 + 0x1c) != 0) {
            puVar11 = (uint *)(plVar8 + 4);
            do {
              plVar12 = (longlong *)((ulonglong)*puVar11 + DAT_000bab08);
              if ((*(uint *)((longlong)plVar12 + 0x1c) & 0x10000) != 0) {
                FUN_000441d0(plVar12);
              }
              *plVar12 = 0;
              uVar14 = uVar14 + 1;
              puVar11 = puVar11 + 1;
            } while (uVar14 < *(uint *)((longlong)plVar8 + 0x1c));
          }
          uVar14 = 0;
          if ((((*(byte *)((longlong)plVar8 + 0x14) & 0x80) != 0) &&
              (DAT_000afec8 != (longlong *)0x0)) &&
             (plVar12 = DAT_000afec8, (ulonglong)DAT_000afec4 != 0)) {
            do {
              if (((*plVar12 != 0) && (plVar1 = (longlong *)plVar12[1], *plVar8 == *plVar1)) &&
                 (((short)plVar8[2] == (short)plVar1[2] && ((short)plVar8[1] == (short)plVar1[1]))))
              {
                lVar7 = (**(code **)(DAT_000afbc8 + 0x70))(*plVar12);
                if (lVar7 == 0) {
                  DAT_000afec8[uVar14 * 2] = 0;
                }
                break;
              }
              uVar14 = uVar14 + 1;
              plVar12 = plVar12 + 2;
            } while (uVar14 < DAT_000afec4);
          }
          uVar10 = 0;
          *plVar8 = 0xffff;
          bVar4 = false;
          bVar5 = false;
          if ((*(byte *)((longlong)plVar8 + 0x14) & 0x20) == 0) {
            bVar4 = bVar6;
            bVar5 = bVar6;
          }
        }
        uVar9 = 0;
        uVar15 = uVar15 + 1;
        bVar6 = bVar5;
      } while (uVar15 < *DAT_000baaf0);
      uVar14 = DAT_000aff60;
      if ((bVar13) && (plVar8 = DAT_000aff70, uVar14 = uVar9, DAT_000aff60 != 0)) {
        do {
          if ((*plVar8 == local_38) && (uVar14 = uVar9, plVar8[1] == local_30)) break;
          uVar9 = uVar9 + 1;
          plVar8 = plVar8 + 2;
          uVar14 = uVar9;
        } while (uVar9 < DAT_000aff60);
      }
    }
    uVar15 = DAT_000aff60;
    uVar9 = 0;
    plVar8 = DAT_000aff80;
    if (DAT_000aff68 != 0) {
      do {
        if ((plVar8[1] == param_1) && (lVar7 = *plVar8, lVar7 != 0)) {
          if ((*(longlong *)(lVar7 + 6) != 0x45eb8cf4f22fc20c) ||
             (*(longlong *)(lVar7 + 0xe) != -0x2ca246afb152f972)) {
            bVar2 = false;
          }
          *(undefined2 *)(DAT_000aff80 + uVar9 * 6 + 2) = 0;
          DAT_000aff80[uVar9 * 6 + 3] = 0;
          *(undefined1 *)(DAT_000aff80 + uVar9 * 6 + 4) = 0;
          *(undefined2 *)(uVar9 * 0x30 + 0x22 + (longlong)DAT_000aff80) = 0;
          plVar8 = DAT_000aff80 + uVar9 * 6;
          if ((plVar8 != (longlong *)0x0) && (*plVar8 != 0)) {
            (**(code **)(DAT_000afbc8 + 0x48))();
            uVar15 = DAT_000aff60;
            *plVar8 = 0;
          }
          if (bVar2) {
            return uVar10;
          }
          if (bVar4) {
            return uVar10;
          }
          if (uVar14 != uVar15) {
            return uVar10;
          }
          FUN_000453c4();
          return uVar10;
        }
        uVar9 = uVar9 + 1;
        plVar8 = plVar8 + 6;
      } while (uVar9 < DAT_000aff68);
    }
  }
  return uVar10;
}

