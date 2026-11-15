
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void WS05_1e6f8(undefined8 param_1)

{
  longlong *plVar1;
  longlong lVar2;
  short *psVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  short *psVar6;
  ulonglong uVar7;
  longlong lVar8;
  short sVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  ulonglong uVar13;
  ulonglong uVar14;
  ulonglong uVar15;
  short local_res8 [4];
  ulonglong local_res10;
  undefined8 *local_res18;
  byte *local_res20;
  undefined8 local_70;
  undefined8 uStack_68;
  undefined2 local_60;
  undefined8 local_5e;
  undefined8 uStack_56;
  undefined4 local_4e;
  undefined2 local_4a;
  
  local_60 = DAT_000a8e40;
  local_4e = 0;
  local_4a = 0;
  local_70 = _DAT_000a8e30;
  uStack_68 = uRam00000000000a8e38;
  local_5e = 0;
  uStack_56 = 0;
  puVar4 = FUN_00059b50(param_1,CONCAT62(DAT_000bab90._2_6_,(short)DAT_000bab90) * 2);
  puVar5 = FUN_00059b50(CONCAT62(DAT_000bab90._2_6_,(short)DAT_000bab90),
                        CONCAT62(DAT_000bab90._2_6_,(short)DAT_000bab90) * 2);
  uVar10 = 0;
  uVar13 = *(ulonglong *)(DAT_000afce8 + 0x78) >> 1;
  lVar8 = *(longlong *)(DAT_000afce8 + 0x70);
  lVar2 = *(longlong *)(DAT_000afd20 + 0x70);
  uVar11 = uVar10;
  uVar14 = uVar10;
  local_res18 = puVar5;
  if (uVar13 != 0) {
    do {
      if (lVar8 != 0) {
        sVar9 = *(short *)(lVar8 + uVar11 * 2);
        psVar6 = FUN_00013298(sVar9);
        if (psVar6 != (short *)0x0) {
          *(short *)((longlong)puVar4 + uVar14 * 2) = sVar9;
          uVar14 = uVar14 + 1;
        }
      }
      uVar11 = uVar11 + 1;
    } while (uVar11 < uVar13);
  }
  uVar12 = *(ulonglong *)(DAT_000afd20 + 0x78) >> 1;
  uVar11 = uVar10;
  uVar13 = uVar10;
  if (uVar12 != 0) {
    do {
      if (lVar2 != 0) {
        sVar9 = *(short *)(lVar2 + uVar11 * 2);
        psVar6 = FUN_00013298(sVar9);
        if (psVar6 != (short *)0x0) {
          *(short *)((longlong)puVar5 + uVar13 * 2) = sVar9;
          uVar13 = uVar13 + 1;
        }
      }
      uVar11 = uVar11 + 1;
    } while (uVar11 < uVar12);
  }
  uVar11 = CONCAT62(DAT_000bab90._2_6_,(short)DAT_000bab90);
  uVar12 = uVar10;
  uVar15 = uVar10;
  if (uVar11 != 0) {
    do {
      lVar8 = DAT_000bab88;
      if (*(char *)(DAT_000bab88 + 0x28 + uVar12) != '\0') {
        local_res20 = FUN_00059e68(*(byte **)(DAT_000bab88 + 0x10 + uVar12));
        uVar11 = uVar10;
        for (psVar6 = *(short **)(lVar8 + 8 + uVar12); *psVar6 != 0; psVar6 = psVar6 + 1) {
          uVar11 = uVar11 + 1;
        }
        uVar7 = (ulonglong)local_res20 & 0xffff;
        local_res10 = uVar7 + uVar11 * 2 + 8;
        puVar5 = FUN_00059b50(psVar6,local_res10);
        *(undefined4 *)puVar5 = *(undefined4 *)(DAT_000bab88 + 4 + uVar12);
        *(short *)((longlong)puVar5 + 4) = (short)local_res20;
        psVar3 = *(short **)(DAT_000bab88 + 8 + uVar12);
        uVar11 = uVar10;
        for (psVar6 = psVar3; *psVar6 != 0; psVar6 = psVar6 + 1) {
          uVar11 = uVar11 + 1;
        }
        FUN_00059244((short *)((longlong)puVar5 + 6),uVar11 + 1,psVar3);
        (**(code **)(DAT_000afbc8 + 0x160))
                  ((longlong)puVar5 + (local_res10 - uVar7),
                   *(undefined8 *)(DAT_000bab88 + 0x10 + uVar12));
        psVar6 = (short *)&local_70;
        uVar11 = uVar10;
        sVar9 = (short)local_70;
        while (sVar9 != 0) {
          psVar6 = psVar6 + 1;
          uVar11 = uVar11 + 1;
          sVar9 = *psVar6;
        }
        FUN_00017908((char *)&local_70,uVar11 * 2 + 2,(byte *)u_Boot_04X_000948c0,
                     (ulonglong)*(ushort *)(DAT_000bab88 + uVar12));
        (**(code **)(DAT_000afbd8 + 0x58))(&local_70,&DAT_000930a0,7,local_res10,puVar5);
        *(undefined1 *)(DAT_000bab88 + 0x28 + uVar12) = 0;
        *(undefined2 *)((longlong)puVar4 + uVar14 * 2) = *(undefined2 *)(DAT_000bab88 + uVar12);
        uVar14 = uVar14 + 1;
        *(undefined2 *)((longlong)local_res18 + uVar13 * 2) = *(undefined2 *)(DAT_000bab88 + uVar12)
        ;
        uVar13 = uVar13 + 1;
        (**(code **)(DAT_000afbc8 + 0x48))(puVar5);
        uVar11 = CONCAT62(DAT_000bab90._2_6_,(short)DAT_000bab90);
      }
      uVar15 = uVar15 + 1;
      uVar12 = uVar12 + 0x48;
    } while (uVar15 < uVar11);
  }
  if (*(longlong *)(DAT_000afce8 + 0x78) == 0) {
    puVar5 = FUN_00059b50(DAT_000afce8,*(ulonglong *)(DAT_000afcd8 + 0x78));
    if (puVar5 != (undefined8 *)0x0) {
      (**(code **)(DAT_000afbc8 + 0x160))
                (puVar5,*(undefined8 *)(DAT_000afcd8 + 0x70),*(undefined8 *)(DAT_000afcd8 + 0x78));
      *(undefined8 **)(DAT_000afce8 + 0x70) = puVar5;
      *(undefined8 *)(DAT_000afce8 + 0x78) = *(undefined8 *)(DAT_000afcd8 + 0x78);
    }
    if (puVar4 != (undefined8 *)0x0) {
      (**(code **)(DAT_000afbc8 + 0x48))(puVar4);
    }
  }
  else {
    plVar1 = (longlong *)(DAT_000afce8 + 0x70);
    if ((plVar1 != (longlong *)0x0) && (*plVar1 != 0)) {
      (**(code **)(DAT_000afbc8 + 0x48))(*plVar1);
      *plVar1 = 0;
    }
    *(undefined8 **)(DAT_000afce8 + 0x70) = puVar4;
    *(ulonglong *)(DAT_000afce8 + 0x78) = uVar14 * 2;
  }
  plVar1 = (longlong *)(DAT_000afd20 + 0x70);
  if ((plVar1 != (longlong *)0x0) && (*plVar1 != 0)) {
    (**(code **)(DAT_000afbc8 + 0x48))(*plVar1);
    *plVar1 = 0;
  }
  *(undefined8 **)(DAT_000afd20 + 0x70) = local_res18;
  *(ulonglong *)(DAT_000afd20 + 0x78) = uVar13 * 2;
  uVar11 = DAT_000baaa0;
  uVar14 = uVar10;
  uVar13 = uVar10;
  if (DAT_000baaa0 != 0) {
    do {
      if (*(char *)(uVar13 + 0x28 + DAT_000baa98) == '\0') {
        psVar6 = (short *)&local_70;
        uVar11 = uVar10;
        sVar9 = (short)local_70;
        while (sVar9 != 0) {
          psVar6 = psVar6 + 1;
          uVar11 = uVar11 + 1;
          sVar9 = *psVar6;
        }
        FUN_00017908((char *)&local_70,uVar11 * 2 + 2,(byte *)u_Boot_04X_000948c0,
                     (ulonglong)*(ushort *)(uVar13 + DAT_000baa98));
        (**(code **)(DAT_000afbd8 + 0x58))(&local_70,&DAT_000930a0,7,0,&local_70);
        uVar11 = DAT_000baaa0;
      }
      uVar14 = uVar14 + 1;
      uVar13 = uVar13 + 0x48;
    } while (uVar14 < uVar11);
  }
  if (DAT_000baa98 != 0) {
    (**(code **)(DAT_000afbc8 + 0x48))();
    DAT_000baa98 = 0;
  }
  local_res8[0] = (short)DAT_000bab90;
  DAT_000baaa0 = 0;
  WS05_1cde4(1,DAT_000afce8,0xb,0,2,(undefined1 *)local_res8);
  WS05_1cde4(1,DAT_000afd20,0xb,0,2,(undefined1 *)local_res8);
  for (lVar8 = CONCAT62(DAT_000bab90._2_6_,(short)DAT_000bab90); local_res8[0] = (short)uVar10,
      lVar8 != 0; lVar8 = lVar8 + -1) {
    uVar10 = (ulonglong)(ushort)(local_res8[0] + 1);
  }
  WS05_1cde4(1,DAT_000afce8,0xc,0,2,(undefined1 *)local_res8);
  WS05_1cde4(1,DAT_000afd20,0xc,0,2,(undefined1 *)local_res8);
  return;
}

