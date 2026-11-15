ulonglong FUN_000320d4(void)
{
  uint uVar1;
  uint *puVar2;
  uint *puVar3;
  ulonglong uVar4;
  longlong *plVar5;
  ulonglong uVar6;
  uint *puVar7;
  ulonglong uVar8;
  uVar4 = 0;
  DAT_001938e0 = (uint *)FUN_000014c8((ulonglong)(DAT_00193690 + DAT_001936a0 + DAT_001936b0));
  if (DAT_001938e0 == (uint *)0x0) {
    uVar4 = 0x8000000000000009;
  }
  else {
    DAT_001801f8 = 1;
    DAT_001937e8 = DAT_001938e0;
    (**(code **)(DAT_00180188 + 0x160))(DAT_001938e0,DAT_00193638,DAT_001936b0);
    (**(code **)(DAT_00180188 + 0x160))
              ((ulonglong)DAT_001936b0 + (longlong)DAT_001938e0,DAT_00193668,DAT_00193690);
    (**(code **)(DAT_00180188 + 0x160))
              ((longlong)DAT_001938e0 + (ulonglong)DAT_001936b0 + (ulonglong)DAT_00193690,
               DAT_00193648,DAT_001936a0);
    puVar2 = DAT_001937e8;
    uVar1 = DAT_001936b0;
    uVar6 = 1;
    DAT_001937e8[1] = DAT_001936b0;
    if (1 < *puVar2) {
      puVar3 = puVar2 + 2;
      do {
        uVar6 = uVar6 + 1;
        *puVar3 = *puVar3 + DAT_00193690 + uVar1;
        puVar3 = puVar3 + 1;
      } while (uVar6 < *puVar2);
    }
    FUN_000013d0(&DAT_00193668);
    FUN_000013d0(&DAT_00193648);
    FUN_000013d0(&DAT_00193638);
    puVar2 = DAT_001937e8;
    uVar6 = uVar4;
    puVar3 = DAT_001938e0;
    if (*DAT_001937e8 != 0) {
      do {
        plVar5 = (longlong *)((ulonglong)puVar2[uVar6 + 1] + (longlong)puVar3);
        puVar7 = puVar3;
        if ((plVar5 != (longlong *)0x0) && (*(int *)((longlong)plVar5 + 0x1c) != 0)) {
          puVar2 = (uint *)(plVar5 + 4);
          uVar8 = uVar4;
          do {
            if (((longlong *)((ulonglong)*puVar2 + DAT_001937f8) != (longlong *)0x0) &&
               (FUN_00034fe8(plVar5,(longlong *)((ulonglong)*puVar2 + DAT_001937f8)),
               puVar7 = DAT_001938e0, puVar3 != DAT_001938e0)) goto LAB_00032265;
            uVar8 = uVar8 + 1;
            puVar2 = puVar2 + 1;
          } while (uVar8 < *(uint *)((longlong)plVar5 + 0x1c));
          puVar2 = DAT_001937e8;
          if (puVar3 != puVar7) {
LAB_00032265:
            uVar6 = uVar6 - 1;
            puVar2 = DAT_001937e8;
          }
        }
        uVar6 = uVar6 + 1;
        puVar3 = puVar7;
      } while (uVar6 < *puVar2);
    }
  }
  return uVar4;
}