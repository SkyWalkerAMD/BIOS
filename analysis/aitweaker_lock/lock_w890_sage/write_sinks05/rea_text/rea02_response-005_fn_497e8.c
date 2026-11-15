
ulonglong WS05_497e8(void)

{
  byte bVar1;
  ulonglong uVar2;
  longlong lVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  undefined8 uVar6;
  uint *puVar7;
  longlong *plVar8;
  undefined1 *puVar9;
  longlong *plVar10;
  uint uVar11;
  ulonglong uVar12;
  uint *puVar13;
  
  uVar12 = 0;
  puVar7 = DAT_000baaf0;
  if (*DAT_000baaf0 != 0) {
    do {
      plVar8 = (longlong *)((ulonglong)puVar7[uVar12 + 1] + (longlong)puVar7);
      if ((*plVar8 != 0) && (puVar9 = (undefined1 *)0x0, *(int *)((longlong)plVar8 + 0x1c) != 0)) {
        puVar13 = (uint *)(plVar8 + 4);
        do {
          plVar10 = (longlong *)((ulonglong)*puVar13 + DAT_000bab08);
          if ((((*(short *)((longlong)plVar10 + 0x14) == 0x16) &&
               (uVar2 = FUN_00049e60((longlong)plVar8,(ulonglong)puVar9), (char)uVar2 == '\0')) &&
              (bVar1 = FUN_00049128((longlong)plVar10), bVar1 == 5)) &&
             ((lVar3 = (**(code **)(DAT_000afbc8 + 0x140))(&DAT_00093628,0), lVar3 == 0 &&
              (DAT_000afe28 != 0)))) {
            puVar4 = FUN_0004bc70(DAT_000babe8,0x4f,(short *)0x0);
            if (*(short *)(plVar10[6] + 2) == -1) {
              puVar5 = (undefined8 *)0x0;
            }
            else {
              puVar5 = FUN_0004bc70(*plVar10,*(short *)(plVar10[6] + 2),(short *)0x0);
            }
            uVar6 = (**(code **)(DAT_000afe28 + 0x20))(puVar4,puVar5,1,0);
            if (puVar4 != (undefined8 *)0x0) {
              uVar6 = (**(code **)(DAT_000afbc8 + 0x48))(puVar4);
            }
            if (puVar5 != (undefined8 *)0x0) {
              uVar6 = (**(code **)(DAT_000afbc8 + 0x48))(puVar5);
            }
            return CONCAT71((int7)((ulonglong)uVar6 >> 8),1);
          }
          register0x00000020 = (BADSPACEBASE *)(ulonglong)*(uint *)((longlong)plVar8 + 0x1c);
          puVar9 = puVar9 + 1;
          puVar13 = puVar13 + 1;
          puVar7 = DAT_000baaf0;
        } while (puVar9 < register0x00000020);
      }
      uVar11 = (int)uVar12 + 1;
      uVar12 = (ulonglong)uVar11;
    } while (uVar11 < *puVar7);
  }
  return (ulonglong)register0x00000020 & 0xffffffffffffff00;
}

