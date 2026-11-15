
ushort * FUN_00004d50(undefined8 *param_1,longlong param_2,longlong param_3,longlong param_4)

{
  char cVar1;
  longlong lVar2;
  char *pcVar3;
  uint uVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;
  longlong lVar7;
  ushort *puVar8;
  byte *pbVar9;
  ushort *puVar10;
  ushort *puVar11;
  uint uVar12;
  longlong *plVar13;
  ushort *puVar14;
  uint uVar15;
  
  puVar11 = (ushort *)0x0;
  puVar8 = puVar11;
  puVar14 = puVar11;
  if (*(longlong *)(param_2 + 0x330) != 0) {
    do {
      lVar2 = *(longlong *)(*(longlong *)(param_2 + 0x338) + (longlong)puVar14 * 8);
      if ((*(char *)(lVar2 + 0x18) == '\x04') && (param_3 == *(longlong *)(lVar2 + 0x28))) {
        pcVar3 = *(char **)(lVar2 + 0x370);
        puVar11 = (ushort *)0x800000000000000e;
        puVar5 = FUN_000186b4(param_4,s_StorageControllers_0001ac20);
        uVar12 = 0;
        if ((puVar5 != (undefined8 *)0x0) && (*(int *)(puVar5 + 3) == 5)) {
          uVar15 = uVar12;
          for (puVar6 = (undefined8 *)puVar5[2]; puVar6 != (undefined8 *)0x0;
              puVar6 = (undefined8 *)*puVar6) {
            uVar15 = uVar15 + 1;
          }
          if (uVar15 != 0) {
            do {
              plVar13 = (longlong *)puVar5[2];
              uVar4 = uVar12;
              if (plVar13 != (longlong *)0x0) {
                do {
                  if ((int)uVar4 < 1) break;
                  plVar13 = (longlong *)*plVar13;
                  uVar4 = uVar4 - 1;
                } while (plVar13 != (longlong *)0x0);
                if (((((plVar13 != (longlong *)0x0) && (*(int *)(puVar5 + 3) == 6)) &&
                     (puVar6 = FUN_000186b4((longlong)plVar13,&DAT_00019eb4),
                     puVar6 != (undefined8 *)0x0)) &&
                    ((*(int *)(puVar6 + 3) == 4 &&
                     (lVar7 = FUN_00015b00(pcVar3,(char *)puVar6[5]), lVar7 == 0)))) &&
                   (puVar6 = FUN_000186b4((longlong)plVar13,s_Assembly_0001a110),
                   puVar6 != (undefined8 *)0x0)) {
                  puVar6 = FUN_000186b4((longlong)puVar6,s__odata_id_00019b40);
                  lVar7 = 0;
                  if ((puVar6 != (undefined8 *)0x0) && (*(int *)(puVar6 + 3) == 4)) {
                    cVar1 = *(char *)puVar6[5];
                    while (cVar1 != '\0') {
                      lVar7 = lVar7 + 1;
                      cVar1 = ((char *)puVar6[5])[lVar7];
                    }
                    puVar8 = (ushort *)FUN_00015ad4(lVar7 * 2 + 2);
                    puVar11 = (ushort *)0x0;
                    if (puVar8 == (ushort *)0x0) {
                      puVar11 = (ushort *)0x8000000000000009;
                      break;
                    }
                    puVar10 = puVar8;
                    for (pbVar9 = (byte *)puVar6[5]; *pbVar9 != 0; pbVar9 = pbVar9 + 1) {
                      *puVar10 = (ushort)*pbVar9;
                      puVar10 = puVar10 + 1;
                    }
                    *puVar10 = 0;
                  }
                }
              }
              uVar12 = uVar12 + 1;
            } while (uVar12 < uVar15);
          }
        }
        if ((longlong)puVar11 < 0) {
          if (puVar11 != (ushort *)0x800000000000000e) {
            return puVar11;
          }
          return (ushort *)0x0;
        }
        puVar11 = (ushort *)FUN_00003f3c((byte *)(lVar2 + 0x1c8),param_1,(short *)puVar8);
        (**(code **)(DAT_0001e070 + 0x48))(puVar8);
        if ((longlong)puVar11 < 0) {
          return puVar11;
        }
      }
      puVar14 = (ushort *)((longlong)puVar14 + 1);
    } while (puVar14 < *(ushort **)(param_2 + 0x330));
  }
  return puVar11;
}

