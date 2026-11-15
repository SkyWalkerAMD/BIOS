
undefined4 FUN_00028250(longlong *param_1)

{
  longlong lVar1;
  bool bVar2;
  uint *puVar3;
  uint uVar4;
  char *pcVar5;
  ulonglong uVar6;
  longlong *plVar7;
  uint *puVar8;
  undefined4 uVar9;
  
  bVar2 = false;
  uVar9 = 0;
  if (param_1 != (longlong *)0x0) {
    pcVar5 = (char *)param_1[6];
    plVar7 = (longlong *)
             ((ulonglong)DAT_001937e8[(ulonglong)*(ushort *)((longlong)param_1 + 0x16) + 1] +
             DAT_001938e0);
    if ((pcVar5 != (char *)0x0) && ((*pcVar5 == '\n' || (*pcVar5 == '\x19')))) {
      pcVar5 = pcVar5 + ((byte)pcVar5[1] & 0x7f);
      if (*pcVar5 == '\x17') {
        pcVar5 = pcVar5 + ((byte)pcVar5[1] & 0x7f);
      }
      if (((*pcVar5 - 0x12U & 0xfd) == 0) && (*plVar7 != 0)) {
        uVar6 = 0;
        if ((ulonglong)*(uint *)((longlong)plVar7 + 0x1c) != 0) {
          puVar8 = (uint *)(plVar7 + 4);
          do {
            if (bVar2) {
              return uVar9;
            }
            if (*(short *)(pcVar5 + 2) == *(short *)((ulonglong)*puVar8 + DAT_001937f8 + 0xc)) {
              uVar9 = *(undefined4 *)((ulonglong)*puVar8 + DAT_001937f8 + 8);
              bVar2 = true;
            }
            uVar6 = uVar6 + 1;
            puVar8 = puVar8 + 1;
          } while (uVar6 < *(uint *)((longlong)plVar7 + 0x1c));
          if (bVar2) {
            return uVar9;
          }
        }
        bVar2 = false;
        uVar4 = 0;
        lVar1 = *param_1;
        puVar8 = DAT_001937e8;
        if (*DAT_001937e8 != 0) {
          do {
            if (bVar2) {
              return uVar9;
            }
            if ((uVar4 != *(ushort *)((longlong)param_1 + 0x16)) &&
               (plVar7 = (longlong *)((ulonglong)puVar8[1] + DAT_001938e0), *plVar7 == lVar1)) {
              uVar6 = 0;
              if ((ulonglong)*(uint *)((longlong)plVar7 + 0x1c) != 0) {
                puVar3 = (uint *)(plVar7 + 4);
                do {
                  if (bVar2) break;
                  param_1 = (longlong *)((ulonglong)*puVar3 + DAT_001937f8);
                  if (*(short *)(pcVar5 + 2) == *(short *)((longlong)param_1 + 0xc)) {
                    uVar9 = (undefined4)param_1[1];
                    bVar2 = true;
                  }
                  uVar6 = uVar6 + 1;
                  puVar3 = puVar3 + 1;
                } while (uVar6 < *(uint *)((longlong)plVar7 + 0x1c));
              }
            }
            uVar4 = uVar4 + 1;
            puVar8 = puVar8 + 1;
          } while (uVar4 < *DAT_001937e8);
          if (bVar2) {
            return uVar9;
          }
        }
      }
    }
  }
  return 0;
}

