undefined8 FUN_00030318(undefined8 param_1,uint param_2)
{
  longlong *plVar1;
  uint uVar2;
  longlong lVar3;
  undefined8 uVar4;
  int iVar5;
  plVar1 = DAT_00193650;
  iVar5 = 0x1000;
  if ((DAT_0018f1da != '\0') && (lVar3 = FUN_000310c8(DAT_00193650,param_2), lVar3 == 0)) {
    return 0;
  }
  if (DAT_001936a0 + param_2 < DAT_001936a4) {
LAB_000303b1:
    (**(code **)(DAT_00180188 + 0x160))((ulonglong)DAT_001936a0 + DAT_00193648,plVar1,param_2);
    uVar2 = DAT_001936a0;
    DAT_001936a0 = DAT_001936a0 + param_2;
    if (DAT_00193638 == (uint *)0x0) {
      DAT_001936b4 = 0x200;
      DAT_00193638 = (uint *)FUN_000014c8(0x200);
      if (DAT_00193638 == (uint *)0x0) goto LAB_0003038d;
      *DAT_00193638 = 1;
      DAT_001936b0 = 0xc;
    }
    else {
      if ((ulonglong)DAT_001936b4 <= (ulonglong)DAT_001936b0 + 4) {
        DAT_00193638 = (uint *)FUN_00001450((longlong)DAT_00193638,(ulonglong)DAT_001936b4,
                                            (ulonglong)(DAT_001936b4 + 0x80));
        if (DAT_00193638 == (uint *)0x0) goto LAB_0003038d;
        DAT_001936b4 = DAT_001936b4 + 0x80;
      }
      DAT_001936b0 = DAT_001936b0 + 4;
    }
    DAT_00193638[(ulonglong)*DAT_00193638 + 1] = uVar2;
    *DAT_00193638 = *DAT_00193638 + 1;
    uVar4 = 0;
  }
  else {
    if (0x1000 < param_2) {
      iVar5 = (param_2 & 0xfffff000) + 0x1000;
    }
    DAT_00193648 = FUN_00001450(DAT_00193648,(ulonglong)DAT_001936a4,
                                (ulonglong)(DAT_001936a4 + iVar5));
    if (DAT_00193648 != 0) {
      DAT_001936a4 = DAT_001936a4 + iVar5;
      goto LAB_000303b1;
    }
LAB_0003038d:
    uVar4 = 0x8000000000000009;
  }
  return uVar4;
}