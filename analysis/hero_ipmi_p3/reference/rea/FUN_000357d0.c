undefined8 FUN_000357d0(longlong *param_1,short param_2,undefined2 *param_3)
{
  uint uVar1;
  longlong lVar2;
  longlong lVar3;
  longlong *plVar4;
  longlong *plVar5;
  uint *puVar6;
  uint uVar7;
  lVar2 = DAT_001937b0;
  if ((DAT_001938e0 != 0) && (DAT_001937b0 != 0)) {
    uVar7 = 0;
    uVar1 = *DAT_001937e8;
    puVar6 = DAT_001937e8;
    if (uVar1 != 0) {
      do {
        puVar6 = puVar6 + 1;
        plVar5 = (longlong *)((ulonglong)*puVar6 + DAT_001938e0);
        if ((((plVar5 != (longlong *)0x0) && (*plVar5 != 0)) && (*plVar5 != 0xffff)) &&
           (((*(short *)((longlong)plVar5 + 10) == param_2 &&
             (plVar4 = (longlong *)
                       ((ulonglong)*(uint *)(lVar2 + 4 + (ulonglong)*(ushort *)(plVar5 + 1) * 4) +
                       lVar2), plVar4 != (longlong *)0x0)) &&
            (lVar3 = FUN_000b1b20(param_1,plVar4,0x10), lVar3 == 0)))) {
          *param_3 = (short)plVar5[2];
          return 0;
        }
        uVar7 = uVar7 + 1;
      } while (uVar7 < uVar1);
    }
  }
  return 0x8000000000000002;
}