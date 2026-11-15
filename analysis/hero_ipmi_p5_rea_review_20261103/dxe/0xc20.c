
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00000c20(void)

{
  int iVar1;
  short *psVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  longlong lVar6;
  undefined8 *puVar7;
  longlong *plVar8;
  uint uVar9;
  longlong lVar10;
  
  lVar6 = DAT_00017b28;
  _DAT_00017c78 = DAT_00017b40;
  DAT_00017c68 = *(longlong *)(DAT_00017b28 + 0x60);
  _DAT_00017c80 = *(undefined8 *)(DAT_00017b28 + 0x58);
  DAT_00017c70 = DAT_00017b28;
  psVar2 = FUN_0000fbc8(&DAT_00016ec0,DAT_00017b20);
  if (psVar2 == (short *)0x0) {
    uVar3 = FUN_00000b90();
    FUN_00000b40();
    uVar9 = in(0x1808);
    uVar4 = FUN_00000aa0();
    while (iVar1 = in(0x1808), (((uVar9 & 0xffffff) + 0x16b) - iVar1 >> 0x17 & 1) == 0) {
      FUN_000002a0();
    }
    uVar5 = FUN_00000aa0();
    lVar10 = (uVar5 - uVar4) * 0x2685;
    if ((uVar3 >> 9 & 1) == 0) {
      FUN_00000b40();
      _DAT_00017c90 = lVar10;
    }
    else {
      FUN_00000b30();
      _DAT_00017c90 = lVar10;
    }
  }
  else {
    _DAT_00017c90 = *(longlong *)(psVar2 + 0xc);
  }
  FUN_000103a0();
  uVar9 = 0;
  *(undefined1 **)(*(longlong *)(lVar6 + 0x58) + 0x68) = &LAB_000128d8;
  plVar8 = DAT_00017ca8;
  if (DAT_00017c98 != 0) {
    do {
      if ((*plVar8 == DAT_00015be0) && (plVar8[1] == DAT_00015be8)) {
        *(undefined1 **)(DAT_00017ca0 + (ulonglong)uVar9 * 8) = &LAB_00012b5c;
        *(undefined1 **)(DAT_00017cb0 + (ulonglong)uVar9 * 8) = &LAB_00012a60;
        return;
      }
      uVar9 = uVar9 + 1;
      plVar8 = plVar8 + 2;
    } while (uVar9 < DAT_00017c98);
  }
  if ((DAT_00017c98 < DAT_00017c9c) || (lVar6 = FUN_000103a0(), lVar6 == 0)) {
    plVar8 = DAT_00017ca8;
    uVar4 = (ulonglong)DAT_00017c98;
    uVar3 = (ulonglong)DAT_00017c98;
    DAT_00017ca8[uVar3 * 2] = DAT_00015be0;
    plVar8[uVar3 * 2 + 1] = DAT_00015be8;
    *(undefined1 **)(DAT_00017ca0 + uVar4 * 8) = &LAB_00012b5c;
    *(undefined1 **)(DAT_00017cb0 + (ulonglong)DAT_00017c98 * 8) = &LAB_00012a60;
    DAT_00017c98 = DAT_00017c98 + 1;
    puVar7 = FUN_0000f984(4,0x10,&DAT_00015be0);
    if (puVar7 != (undefined8 *)0x0) {
      (**(code **)(DAT_00017c68 + 0xc0))(&DAT_00015be0,puVar7);
    }
  }
  return;
}

