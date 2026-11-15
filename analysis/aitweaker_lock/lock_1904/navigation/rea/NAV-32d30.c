
void Candidate_PreRenderUpdate(uint param_1)

{
  longlong lVar1;
  longlong lVar2;
  ushort uVar3;
  uint uVar4;
  short *psVar5;
  int *piVar6;
  ulonglong uVar7;
  longlong lVar8;
  ushort uVar9;
  longlong lVar10;
  ulonglong uVar11;
  ushort uVar12;
  undefined2 *puVar13;
  short *psVar14;
  short *psVar15;
  ulonglong uVar16;
  
  uVar9 = 0x35;
  uVar3 = 0xc;
  uVar11 = 0;
  piVar6 = (int *)PTR_DAT_0006b7f0;
  do {
    if (*piVar6 == 1) break;
    uVar4 = (int)uVar11 + 1;
    uVar11 = (ulonglong)uVar4;
    piVar6 = piVar6 + 6;
  } while (uVar4 < 6);
  lVar8 = *(longlong *)
           (*(longlong *)(*(longlong *)(DAT_00082748 + 0x30) + (ulonglong)param_1 * 8) + 0x50);
  lVar10 = *(longlong *)(lVar8 + uVar11 * 8);
  uVar11 = 0;
  piVar6 = (int *)PTR_DAT_0006b7f0;
  do {
    if (*piVar6 == 5) break;
    uVar4 = (int)uVar11 + 1;
    uVar11 = (ulonglong)uVar4;
    piVar6 = piVar6 + 6;
  } while (uVar4 < 6);
  lVar1 = *(longlong *)(lVar8 + uVar11 * 8);
  uVar11 = 0;
  piVar6 = (int *)PTR_DAT_0006b7f0;
  do {
    if (*piVar6 == 4) break;
    uVar4 = (int)uVar11 + 1;
    uVar11 = (ulonglong)uVar4;
    piVar6 = piVar6 + 6;
  } while (uVar4 < 6);
  lVar2 = *(longlong *)(lVar8 + uVar11 * 8);
  uVar11 = 0;
  piVar6 = (int *)PTR_DAT_0006b7f0;
  do {
    if (*piVar6 == 0) break;
    uVar4 = (int)uVar11 + 1;
    uVar11 = (ulonglong)uVar4;
    piVar6 = piVar6 + 6;
  } while (uVar4 < 6);
  lVar8 = *(longlong *)(lVar8 + uVar11 * 8);
  uVar12 = 0x15;
  uVar11 = 3;
  uVar16 = 0x50;
  if ((DAT_0006abe8 == 0x1f) || (DAT_0006abe8 == 0x19)) {
    uVar7 = 100;
    if (DAT_0006abf0 == 100) {
      uVar16 = 100;
      uVar9 = 0x42;
      uVar3 = 0xf;
      uVar12 = 0x1c;
      goto LAB_00032e5c;
    }
    if (DAT_0006abf0 == 0x50) goto LAB_00032e5c;
  }
  uVar7 = DAT_0006abf0 * 2;
  uVar16 = DAT_0006abf0 & 0xffff;
  uVar3 = (ushort)(DAT_0006abe8 >> 1);
  uVar12 = (short)DAT_0006abe8 - 3;
  uVar9 = (ushort)(uVar7 / 3);
LAB_00032e5c:
  psVar5 = (short *)FUN_0003eea8(uVar7,DAT_0006abf0 * 2 + 2);
  if (psVar5 != (short *)0x0) {
    FUN_00006ba4(*(ushort *)(lVar10 + 0x2c),*(ushort *)(lVar10 + 0x2a),
                 *(byte *)(lVar10 + 0x31) | *(byte *)(lVar10 + 0x30));
    FUN_00006ba4(*(ushort *)(lVar1 + 0x2c),*(ushort *)(lVar1 + 0x2a),
                 *(byte *)(lVar1 + 0x31) | *(byte *)(lVar1 + 0x30));
    FUN_00006ba4(*(ushort *)(lVar2 + 0x2c),*(ushort *)(lVar2 + 0x2a),
                 *(byte *)(lVar2 + 0x31) | *(byte *)(lVar2 + 0x30));
    if (DAT_00092b38 != 0) {
      uVar7 = *(ushort *)(lVar8 + 0x2a) * DAT_0006abf0;
      if (uVar7 != 0) {
        FUN_00000360((undefined8 *)(DAT_00092b38 + 4 + *(ushort *)(lVar8 + 0x2c) * DAT_0006abf0),
                     uVar7,0);
      }
      lVar10 = *(ushort *)(lVar8 + 0x2a) * DAT_0006abf0;
      puVar13 = (undefined2 *)
                (DAT_00092b38 + *(ushort *)(lVar8 + 0x2c) * DAT_0006abf0 * 2 + 0x3d0904);
      if (lVar10 != 0) {
        for (; lVar10 != 0; lVar10 = lVar10 + -1) {
          *puVar13 = 0x20;
          puVar13 = puVar13 + 1;
        }
      }
    }
    FUN_00006ba4(2,uVar12,0x71);
    uVar4 = (uint)uVar12;
    FUN_0000c99c(0,2,uVar16,(ulonglong)uVar4,0x71);
    if (uVar16 != 0) {
      FUN_0000c7f8(0,2,uVar16,(ulonglong)uVar4);
    }
    psVar15 = psVar5 + 1;
    lVar8 = DAT_0006abf0 - 1;
    psVar14 = psVar15;
    if (lVar8 != 0) {
      for (; lVar8 != 0; lVar8 = lVar8 + -1) {
        *psVar14 = 0x2500;
        psVar14 = psVar14 + 1;
      }
    }
    uVar16 = (ulonglong)uVar9;
    *psVar15 = 0;
    *psVar5 = 0x252c;
    FUN_00004b30(uVar16,2,psVar5,0);
    *psVar5 = 0x2534;
    FUN_00004b30((ulonglong)uVar9,(ulonglong)uVar4 + 1,psVar5,0);
    *psVar5 = 0x2502;
    if (3 < (ushort)(uVar12 + 1)) {
      uVar7 = (ulonglong)(ushort)(uVar12 - 2);
      do {
        FUN_00004b30(uVar16,uVar11,psVar5,0);
        uVar11 = uVar11 + 1;
        uVar7 = uVar7 - 1;
      } while (uVar7 != 0);
    }
    lVar8 = DAT_0006abf0 - 1;
    if (lVar8 != 0) {
      for (; lVar8 != 0; lVar8 = lVar8 + -1) {
        *psVar15 = 0x2500;
        psVar15 = psVar15 + 1;
      }
    }
    *psVar5 = 0x2502;
    psVar5[(DAT_0006abf0 - uVar16) + -1] = 0;
    FUN_00004b30(uVar16,(ulonglong)uVar3,psVar5,0);
    uVar11 = (ulonglong)(int)((ushort)(uVar12 + 1) - 1);
    if (DAT_0006ac48 == 0xffff) {
      DAT_0006ac48 = uVar11;
    }
    DAT_0006ac50 = 0;
    if (DAT_0006ac48 < uVar11) {
      DAT_0006ac48 = uVar11;
    }
    (**(code **)(DAT_000824c8 + 0x48))(psVar5);
  }
  return;
}

