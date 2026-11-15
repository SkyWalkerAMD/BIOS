
void FUN_000367c0(longlong param_1)

{
  longlong *plVar1;
  uint *puVar2;
  ulonglong uVar3;
  
  uVar3 = 0;
  puVar2 = DAT_001937e8;
  if (*DAT_001937e8 != 0) {
    do {
      plVar1 = (longlong *)((ulonglong)puVar2[uVar3 + 1] + DAT_001938e0);
      if ((((plVar1 != (longlong *)0x0) && (*plVar1 != 0)) && (*plVar1 != 0xffff)) &&
         (*plVar1 == param_1)) {
        FUN_000366b8(plVar1);
        puVar2 = DAT_001937e8;
      }
      uVar3 = uVar3 + 1;
    } while (uVar3 < *puVar2);
  }
  return;
}

