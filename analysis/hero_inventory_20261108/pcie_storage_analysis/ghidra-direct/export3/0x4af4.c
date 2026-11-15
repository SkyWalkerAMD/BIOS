
ushort * FUN_00004af4(undefined8 *param_1,longlong param_2,longlong param_3,longlong param_4,
                     ulonglong param_5)

{
  char cVar1;
  byte bVar2;
  longlong lVar3;
  longlong lVar4;
  char *pcVar5;
  undefined8 *puVar6;
  ushort *puVar7;
  byte *pbVar8;
  ushort *puVar9;
  ushort *puVar10;
  ushort *puVar11;
  ulonglong uVar12;
  ushort *puVar13;
  char *local_48 [2];
  
  puVar13 = (ushort *)0x0;
  local_48[0] = (char *)0x0;
  puVar11 = (ushort *)0x800000000000000e;
  puVar6 = FUN_000186b4(param_3,s_Volumes_0001ac38);
  puVar7 = puVar13;
  if (((puVar6 != (undefined8 *)0x0) &&
      (puVar6 = FUN_000186b4((longlong)puVar6,s__odata_id_00019b40), puVar7 = (ushort *)0x0,
      puVar6 != (undefined8 *)0x0)) && (*(int *)(puVar6 + 3) == 4)) {
    cVar1 = *(char *)puVar6[5];
    puVar11 = puVar13;
    while (cVar1 != '\0') {
      puVar11 = (ushort *)((longlong)puVar11 + 1);
      cVar1 = ((char *)puVar6[5])[(longlong)puVar11];
    }
    puVar7 = (ushort *)FUN_00015ad4((longlong)puVar11 * 2 + 2);
    if (puVar7 == (ushort *)0x0) {
      return (ushort *)0x8000000000000009;
    }
    puVar11 = puVar7;
    for (pbVar8 = (byte *)puVar6[5]; *pbVar8 != 0; pbVar8 = pbVar8 + 1) {
      *puVar11 = (ushort)*pbVar8;
      puVar11 = puVar11 + 1;
    }
    *puVar11 = 0;
    puVar11 = puVar13;
  }
  if ((-1 < (longlong)puVar11) && (puVar9 = *(ushort **)(param_2 + 0x330), puVar9 != (ushort *)0x0))
  {
    do {
      lVar3 = *(longlong *)(*(longlong *)(param_2 + 0x338) + (longlong)puVar13 * 8);
      if (*(char *)(lVar3 + 0x18) == '\x06') {
        puVar10 = (ushort *)0x0;
        if (puVar9 != (ushort *)0x0) {
          do {
            lVar4 = *(longlong *)(*(longlong *)(param_2 + 0x338) + (longlong)puVar10 * 8);
            if ((*(char *)(lVar4 + 0x18) == '\x05') &&
               (*(longlong *)(lVar4 + 0x10) == *(longlong *)(lVar3 + 0x78))) {
              if (*(int *)(lVar4 + 0x100) != 3) {
                pbVar8 = (byte *)0x0;
                puVar6 = (undefined8 *)FUN_00016b80();
                if (puVar6 == (undefined8 *)0x0) {
                  return (ushort *)0x8000000000000009;
                }
                *(undefined4 *)(puVar6 + 3) = 6;
                puVar11 = (ushort *)
                          FUN_0000a824((longlong)puVar6,param_2,(byte *)(lVar3 + 0x28),param_5);
                uVar12 = 0;
                if (-1 < (longlong)puVar11) {
                  pbVar8 = FUN_0001784c((longlong)puVar6,0,1,(longlong *)0x0);
                  if (pbVar8 == (byte *)0x0) {
                    puVar11 = (ushort *)0x8000000000000009;
                  }
                  else {
                    bVar2 = *pbVar8;
                    while (bVar2 != 0) {
                      uVar12 = uVar12 + 1;
                      bVar2 = pbVar8[uVar12];
                    }
                    puVar11 = (ushort *)
                              FUN_00019384(param_1,(short *)puVar7,(char *)pbVar8,uVar12,local_48);
                  }
                }
                FUN_00016bcc(puVar6);
                if (pbVar8 != (byte *)0x0) {
                  (**(code **)(DAT_0001e070 + 0x48))(pbVar8);
                }
                pcVar5 = local_48[0];
                if ((longlong)puVar11 < 0) {
                  return puVar11;
                }
                if (local_48[0] == (char *)0x0) {
                  return puVar11;
                }
                puVar11 = (ushort *)
                          FUN_00000708(param_4,local_48[0],
                                       *(undefined8 *)
                                        (*(longlong *)
                                          (*(longlong *)(param_2 + 0x338) + (longlong)puVar13 * 8) +
                                        0x10));
                (**(code **)(DAT_0001e070 + 0x48))(pcVar5);
                local_48[0] = (char *)0x0;
                if ((longlong)puVar11 < 0) {
                  return puVar11;
                }
              }
              break;
            }
            puVar10 = (ushort *)((longlong)puVar10 + 1);
          } while (puVar10 < puVar9);
        }
      }
      puVar9 = *(ushort **)(param_2 + 0x330);
      puVar13 = (ushort *)((longlong)puVar13 + 1);
    } while (puVar13 < puVar9);
  }
  return puVar11;
}

