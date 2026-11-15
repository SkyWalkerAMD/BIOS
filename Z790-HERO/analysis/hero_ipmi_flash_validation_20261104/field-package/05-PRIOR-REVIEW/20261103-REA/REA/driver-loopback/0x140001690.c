
bool FUN_140001690(longlong param_1,ulonglong param_2)

{
  undefined4 *puVar1;
  char cVar2;
  uint uVar3;
  undefined8 uVar4;
  bool bVar5;
  int iVar6;
  ulonglong uVar7;
  bool bVar8;
  int local_44;
  
  bVar5 = false;
  if ((0xffffffffff800016 < param_2 - 0x800001 && param_1 != 0) &&
     (uVar3 = FUN_140003e30((undefined4 *)(param_1 + 0x10)), bVar5 = false, uVar3 == param_2)) {
    uVar7 = 0x14;
    bVar5 = false;
    iVar6 = 0;
    local_44 = 0;
    do {
      if (param_2 - uVar7 < 4) {
        return false;
      }
      puVar1 = (undefined4 *)(param_1 + uVar7);
      uVar3 = FUN_140003e30(puVar1);
      uVar3 = uVar3 & 0xffffff;
      if (uVar3 < 4) {
        return false;
      }
      if (param_2 - uVar7 < (ulonglong)uVar3) {
        return false;
      }
      cVar2 = *(char *)((longlong)puVar1 + 3);
      if (cVar2 == '\x02') {
        if (uVar3 == 0x4fb41) {
          uVar4 = FUN_140003af0((longlong)puVar1,0x1400060e0,0x4fb41);
          bVar8 = (int)uVar4 != 0;
          cVar2 = *(char *)((longlong)puVar1 + 3);
        }
        else {
          cVar2 = '\x02';
          bVar8 = false;
        }
        local_44 = local_44 + 1;
        iVar6 = iVar6 + (uint)bVar8;
      }
      if (cVar2 == -0x21) {
        if (uVar3 != 4) {
          return false;
        }
        bVar5 = true;
        if (uVar7 + 4 != param_2) {
          return false;
        }
      }
      uVar7 = uVar7 + uVar3;
    } while (uVar7 < param_2);
    bVar5 = bVar5 && (iVar6 == 1 && local_44 == 1);
  }
  return bVar5;
}

