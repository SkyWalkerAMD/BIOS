
void FUN_000366b8(longlong *param_1)

{
  byte bVar1;
  undefined8 uVar2;
  longlong *plVar3;
  uint *puVar4;
  ulonglong uVar5;
  
  if ((((param_1 != (longlong *)0x0) && (*param_1 != 0)) && (*param_1 != 0xffff)) &&
     (uVar5 = 0, *(int *)((longlong)param_1 + 0x1c) != 0)) {
    puVar4 = (uint *)(param_1 + 4);
    do {
      plVar3 = (longlong *)((ulonglong)*puVar4 + DAT_001937f8);
      if (((plVar3 != (longlong *)0x0) && (plVar3[5] != 0)) &&
         ((plVar3[6] != 0 &&
          ((uVar2 = FUN_0002a7e4((longlong)plVar3), (char)uVar2 != '\0' &&
           (bVar1 = FUN_00036f08((longlong)plVar3), bVar1 == 7)))))) {
        if ((*(uint *)((longlong)plVar3 + 0x1c) & 0x10000) != 0) {
          FUN_000359ac(plVar3);
        }
        FUN_0010749e((undefined4 *)((longlong)plVar3 + 0x1c),4,0);
      }
      uVar5 = uVar5 + 1;
      puVar4 = puVar4 + 1;
    } while (uVar5 < *(uint *)((longlong)param_1 + 0x1c));
  }
  return;
}

