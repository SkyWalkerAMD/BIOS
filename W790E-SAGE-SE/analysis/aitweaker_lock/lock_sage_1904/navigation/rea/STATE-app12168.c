
ulonglong FUN_00012168(longlong param_1,longlong param_2)

{
  ulonglong uVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  
  uVar1 = 0;
  uVar4 = 0x8000000000000003;
  uVar2 = uVar1;
  if (*(longlong *)(param_1 + 0x38) != 0) {
    do {
      uVar4 = (*(code *)PTR_FUN_0006b9f0)
                        (*(undefined8 *)(*(longlong *)(param_1 + 0x40) + uVar2 * 8),param_2);
      if (-1 < (longlong)uVar4) goto LAB_0001226e;
      uVar2 = (ulonglong)((int)uVar2 + 1);
    } while (uVar2 < *(ulonglong *)(param_1 + 0x38));
  }
  if (DAT_0006b598 == 0x1f) {
    if ((DAT_0006b5a0 == 100) &&
       (uVar2 = uVar1, (*(ulonglong *)(param_1 + 0x48) & 0xfffffffffffffffe) != 0)) {
      do {
        uVar4 = (*(code *)PTR_FUN_0006b9c0)
                          (*(undefined8 *)(*(longlong *)(param_1 + 0x50) + uVar2 * 8),param_2);
        if (-1 < (longlong)uVar4) {
          return uVar4;
        }
        uVar2 = (ulonglong)((int)uVar2 + 1);
      } while (uVar2 < *(ulonglong *)(param_1 + 0x48) >> 1);
    }
  }
  else if ((DAT_0006b598 == 0x18) && (DAT_0006b5a0 == 0x50)) {
    uVar2 = *(ulonglong *)(param_1 + 0x48);
    uVar3 = uVar2 >> 1;
    while( true ) {
      if (uVar2 - 1 <= (uVar3 & 0xffffffff)) break;
      uVar4 = (*(code *)PTR_FUN_0006b9c0)
                        (*(undefined8 *)(*(longlong *)(param_1 + 0x50) + (uVar3 & 0xffffffff) * 8),
                         param_2);
      if (-1 < (longlong)uVar4) {
        return uVar4;
      }
      uVar2 = *(ulonglong *)(param_1 + 0x48);
      uVar3 = (ulonglong)((int)uVar3 + 1);
    }
  }
LAB_0001226e:
  if (((uVar4 != 0) && (*(short *)(param_2 + 8) == 1)) &&
     (((*(int *)(param_2 + 0x18) == 0x1f ||
       ((*(int *)(param_2 + 0x18) == 0x67 || (*(int *)(param_2 + 0x18) == 0x55)))) ||
      ((*(short *)(param_2 + 0xc) == 0 && (*(short *)(param_2 + 0xe) == 0)))))) {
    uVar4 = uVar1;
  }
  return uVar4;
}

