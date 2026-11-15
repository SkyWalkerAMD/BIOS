
undefined8 FUN_0001974c(uint param_1,uint param_2,uint param_3,uint param_4,uint *param_5)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  bool bVar14;
  
  bVar14 = param_4 <= param_2;
  if (param_2 == param_4) {
    bVar14 = param_3 <= param_1;
  }
  if (bVar14) {
    if (param_4 == 0) {
      iVar3 = LZCOUNT(param_3) + 0x20;
    }
    else {
      iVar3 = LZCOUNT(param_4);
    }
    if (param_2 == 0) {
      iVar5 = LZCOUNT(param_1) + 0x20;
    }
    else {
      iVar5 = LZCOUNT(param_2);
    }
    uVar6 = iVar3 - iVar5;
    uVar13 = uVar6 - 0x20;
    uVar4 = 0x20 - uVar6;
    uVar10 = param_4 << (uVar6 & 0xff) | param_3 << (uVar13 & 0xff) | param_3 >> (uVar4 & 0xff);
    bVar14 = uVar10 <= param_2;
    param_3 = param_3 << (uVar6 & 0xff);
    if (param_2 == uVar10) {
      bVar14 = param_3 <= param_1;
    }
    if (bVar14) {
      bVar14 = param_1 < param_3;
      param_1 = param_1 - param_3;
      param_2 = param_2 - (uVar10 + bVar14);
      uVar2 = 1 << (uVar13 & 0xff) | 1U >> (uVar4 & 0xff);
      uVar1 = 1 << (uVar6 & 0xff);
    }
    else {
      uVar1 = 0;
      uVar2 = uVar1;
    }
    if (uVar6 != 0) {
      uVar11 = param_3 >> 1 | uVar10 << 0x1f;
      uVar10 = uVar10 >> 1;
      uVar7 = param_1;
      uVar8 = param_2;
      uVar12 = uVar6;
      do {
        bVar14 = uVar10 <= uVar8;
        if (uVar8 == uVar10) {
          bVar14 = uVar11 <= uVar7;
        }
        if (bVar14) {
          bVar14 = uVar7 < uVar11;
          uVar9 = uVar7 - uVar11;
          uVar7 = uVar9 * 2 + 1;
          uVar8 = (uVar8 - (uVar10 + bVar14)) * 2 + (uint)CARRY4(uVar9,uVar9) +
                  (uint)(0xfffffffe < uVar9 * 2);
        }
        else {
          bVar14 = CARRY4(uVar7,uVar7);
          uVar7 = uVar7 * 2;
          uVar8 = uVar8 * 2 + (uint)bVar14;
        }
        uVar12 = uVar12 - 1;
      } while (uVar12 != 0);
      param_1 = uVar7 >> (uVar6 & 0xff) | uVar8 << (uVar4 & 0xff) | uVar8 >> (uVar13 & 0xff);
      bVar14 = CARRY4(uVar1,uVar7);
      uVar7 = uVar1 + uVar7;
      param_2 = uVar8 >> (uVar6 & 0xff);
      uVar10 = param_1 << (uVar6 & 0xff);
      uVar1 = uVar7 - uVar10;
      uVar2 = (uVar2 + uVar8 + (uint)bVar14) -
              ((param_2 << (uVar6 & 0xff) | param_1 << (uVar13 & 0xff) | param_1 >> (uVar4 & 0xff))
              + (uint)(uVar7 < uVar10));
    }
  }
  else {
    uVar1 = 0;
    uVar2 = uVar1;
  }
  if (param_5 == (uint *)0x0) {
    return CONCAT44(uVar2,uVar1);
  }
  *param_5 = param_1;
  param_5[1] = param_2;
  return CONCAT44(uVar2,uVar1);
}

