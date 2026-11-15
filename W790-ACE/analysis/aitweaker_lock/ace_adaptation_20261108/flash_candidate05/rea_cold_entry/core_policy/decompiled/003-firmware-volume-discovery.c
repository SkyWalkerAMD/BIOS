
undefined8 * Candidate_ACE1904_firmware_volume_discovery(longlong *param_1)

{
  undefined8 *puVar1;
  bool bVar2;
  ulonglong uVar3;
  longlong lVar4;
  ulonglong uVar5;
  uint *puVar6;
  undefined **ppuVar7;
  undefined8 *puVar8;
  short sVar9;
  uint uVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  ulonglong uVar13;
  ulonglong local_res10;
  ulonglong local_res18;
  longlong local_res20;
  undefined *local_48;
  undefined *local_40;
  
  uVar13 = 0;
  local_res10 = 0;
  bVar2 = false;
  uVar3 = FUN_00004f64(param_1,(longlong *)&DAT_000159a0,&local_res20,DAT_00017a80,(longlong *)0x0,1
                      );
  if (((longlong)uVar3 < 0) ||
     (lVar4 = FUN_0000dcd4(local_res20,(longlong *)&local_res10), uVar3 = local_res10, lVar4 < 0))
  goto LAB_00009f0b;
  sVar9 = 0;
  uVar11 = (ulonglong)(*(ushort *)(local_res10 + 0x30) >> 1);
  uVar5 = uVar13;
  bVar2 = false;
  if (uVar11 != 0) {
    do {
      sVar9 = sVar9 + *(short *)(local_res10 + uVar5 * 2);
      uVar5 = uVar5 + 1;
    } while (uVar5 < uVar11);
    if (sVar9 != 0) goto LAB_00009ed6;
  }
  if (*(short *)(local_res10 + 0x34) != 0) {
    uVar10 = (uint)*(ushort *)(local_res10 + 0x34);
    puVar6 = (uint *)(local_res10 + 0x38);
    local_res18 = 0;
    local_res10 = 0;
    uVar5 = uVar13;
    do {
      if ((*puVar6 == 0) && (puVar6[1] == 0)) goto LAB_00009eab;
      uVar12 = (ulonglong)*puVar6;
      uVar11 = uVar13;
      if (uVar12 != 0) {
        do {
          local_res18 = uVar5;
          if (uVar10 < puVar6[1]) break;
          uVar10 = uVar10 - puVar6[1];
          uVar5 = uVar5 + 1;
          uVar11 = uVar11 + 1;
          local_res18 = uVar5;
        } while (uVar11 < uVar12);
      }
      if (uVar11 < uVar12) goto LAB_00009ea5;
      puVar6 = puVar6 + 2;
    } while( true );
  }
  goto LAB_00009ed6;
LAB_00009ea5:
  local_res10 = (ulonglong)uVar10;
LAB_00009eab:
  lVar4 = FUN_0000db98(local_res20,(longlong *)&local_res18,&local_res10,0x10,(longlong)&local_48);
  bVar2 = false;
  if (-1 < lVar4) {
    bVar2 = true;
  }
LAB_00009ed6:
  FUN_0000bbe8(uVar3);
  if ((bVar2) &&
     (ppuVar7 = (undefined **)PTR_LOOP_00016b88,
     (undefined **)PTR_LOOP_00016b88 != &PTR_LOOP_00016b88)) {
    do {
      if ((local_48 == ppuVar7[3]) && (local_40 == ppuVar7[4])) {
        return (undefined8 *)0x0;
      }
      ppuVar7 = (undefined **)*ppuVar7;
    } while (ppuVar7 != &PTR_LOOP_00016b88);
  }
LAB_00009f0b:
  puVar8 = FUN_0001084c(4,0x30);
  *puVar8 = 0x776f6e6b;
  puVar8[3] = param_1;
  if (bVar2) {
    puVar8[4] = local_48;
    puVar8[5] = local_40;
  }
  puVar1 = puVar8 + 1;
  *puVar1 = &PTR_LOOP_00016b88;
  puVar8[2] = PTR_LOOP_00016b90;
  *(undefined8 **)PTR_LOOP_00016b90 = puVar1;
  PTR_LOOP_00016b90 = (undefined *)puVar1;
  return puVar8;
}

