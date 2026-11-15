
undefined8 Original_AppDestructor(longlong param_1,char param_2)

{
  longlong *plVar1;
  longlong lVar2;
  undefined7 in_register_00000011;
  uint uVar3;
  ulonglong uVar4;
  
  if (*(longlong *)(param_1 + 0x20) != 0) {
    (*(code *)PTR_FUN_00093dc8)(*(longlong *)(param_1 + 0x20),CONCAT71(in_register_00000011,1));
  }
  *(undefined8 *)(param_1 + 0x20) = 0;
  uVar4 = 0;
  DAT_000baa90 = 0;
  if (*(int *)(param_1 + 0x2c) != 0) {
    do {
      lVar2 = *(longlong *)(*(longlong *)(param_1 + 0x30) + uVar4 * 8);
      if (lVar2 != 0) {
        (*(code *)PTR_FUN_00093de8)(lVar2,1);
      }
      uVar3 = (int)uVar4 + 1;
      uVar4 = (ulonglong)uVar3;
    } while (uVar3 < *(uint *)(param_1 + 0x2c));
  }
  plVar1 = (longlong *)(param_1 + 0x30);
  if ((*plVar1 != 0) && (plVar1 != (longlong *)0x0)) {
    (**(code **)(DAT_000afbc8 + 0x48))();
    *plVar1 = 0;
  }
  uVar4 = 0;
  if (*(longlong *)(param_1 + 0x38) != 0) {
    do {
      (*(code *)PTR_FUN_00093ea8)(*(undefined8 *)(*(longlong *)(param_1 + 0x40) + uVar4 * 8),1);
      uVar4 = (ulonglong)((int)uVar4 + 1);
    } while (uVar4 < *(ulonglong *)(param_1 + 0x38));
  }
  uVar4 = 0;
  if (*(longlong *)(param_1 + 0x48) != 0) {
    do {
      (*(code *)PTR_FUN_00093e78)(*(undefined8 *)(*(longlong *)(param_1 + 0x50) + uVar4 * 8),1);
      uVar4 = (ulonglong)((int)uVar4 + 1);
    } while (uVar4 < *(ulonglong *)(param_1 + 0x48));
  }
  plVar1 = (longlong *)(param_1 + 0x40);
  if ((*plVar1 != 0) && (plVar1 != (longlong *)0x0)) {
    (**(code **)(DAT_000afbc8 + 0x48))();
    *plVar1 = 0;
  }
  plVar1 = (longlong *)(param_1 + 0x50);
  if ((*plVar1 != 0) && (plVar1 != (longlong *)0x0)) {
    (**(code **)(DAT_000afbc8 + 0x48))();
    *plVar1 = 0;
  }
  (*(code *)PTR_FUN_00093ed8)(param_1,0);
  if (param_2 != '\0') {
    (**(code **)(DAT_000afbc8 + 0x48))(param_1);
  }
  return 0;
}

