undefined8 FUN_00031348(longlong param_1,longlong *param_2,undefined4 param_3)
{
  ushort uVar1;
  longlong lVar2;
  uint *puVar3;
  uint uVar4;
  ulonglong uVar5;
  longlong *plVar6;
  uint uVar7;
  uVar5 = 0;
  uVar7 = 1;
  if (*(int *)((longlong)param_2 + 0x1c) != 0) {
    do {
      lVar2 = (ulonglong)*(uint *)((longlong)param_2 + uVar5 * 4 + 0x20) + DAT_001937f8;
      if (*(short *)(lVar2 + 0x18) == *(short *)(lVar2 + 0x16)) {
        *(undefined2 *)(lVar2 + 0x18) = *(undefined2 *)(param_1 + 0x10);
      }
      uVar4 = (int)uVar5 + 1;
      uVar5 = (ulonglong)uVar4;
      *(undefined2 *)(lVar2 + 0x16) = *(undefined2 *)(param_1 + 0x10);
    } while (uVar4 < *(uint *)((longlong)param_2 + 0x1c));
  }
  puVar3 = DAT_00193638;
  if (1 < *DAT_00193638) {
    do {
      plVar6 = (longlong *)((ulonglong)puVar3[(ulonglong)uVar7 + 1] + DAT_00193648);
      if (*plVar6 == *param_2) {
        uVar5 = 0;
        if (*(int *)((longlong)plVar6 + 0x1c) != 0) {
          do {
            lVar2 = (ulonglong)*(uint *)((longlong)plVar6 + uVar5 * 4 + 0x20) + DAT_001937f8;
            uVar1 = FUN_0002d124((ulonglong)*(ushort *)((longlong)param_2 + 10));
            if (uVar1 == *(ushort *)(lVar2 + 0x18)) {
              *(undefined2 *)(lVar2 + 0x18) = *(undefined2 *)(param_1 + 0x10);
            }
            uVar4 = (int)uVar5 + 1;
            uVar5 = (ulonglong)uVar4;
            puVar3 = DAT_00193638;
          } while (uVar4 < *(uint *)((longlong)plVar6 + 0x1c));
        }
        if (*(short *)((longlong)plVar6 + 0x12) == (short)param_2[2]) {
          *(undefined2 *)((longlong)plVar6 + 0x12) = *(undefined2 *)(param_1 + 0x10);
          puVar3 = DAT_00193638;
        }
      }
      uVar7 = uVar7 + 1;
    } while (uVar7 < *puVar3);
  }
  *(undefined2 *)(param_2 + 2) = *(undefined2 *)(param_1 + 0x10);
  (**(code **)(DAT_00180188 + 0x160))(param_1,param_2,param_3);
  return 0;
}