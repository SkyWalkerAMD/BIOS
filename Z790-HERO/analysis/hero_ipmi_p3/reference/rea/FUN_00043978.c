
void FUN_00043978(longlong param_1,uint param_2)

{
  longlong lVar1;
  ushort uVar2;
  uint *puVar3;
  ulonglong uVar4;
  longlong lVar5;
  uint uVar6;
  longlong *plVar7;
  
  if (param_2 < *DAT_001937f0) {
    uVar4 = (ulonglong)param_2 << 4;
    DAT_001801c0 = FUN_00001450(DAT_001801c0,uVar4,(ulonglong)*DAT_001937f0 << 4);
    DAT_001801f0 = FUN_00001450(DAT_001801f0,uVar4,(ulonglong)*DAT_001937f0 << 4);
    DAT_00180210 = FUN_00001450(DAT_00180210,uVar4,(ulonglong)*DAT_001937f0 << 4);
    uVar6 = param_2;
    if (param_2 < *DAT_001937f0) {
      do {
        lVar5 = (ulonglong)uVar6 * 0x10;
        lVar1 = FUN_0001a908((ulonglong)uVar6,(ulonglong *)(DAT_001801c0 + 8 + lVar5));
        *(longlong *)(lVar5 + DAT_001801c0) = lVar1;
        lVar1 = *(longlong *)(lVar5 + 8 + DAT_001801c0);
        if (lVar1 == 0) {
          *(undefined8 *)(lVar5 + DAT_00180210) = 0;
          *(undefined8 *)(lVar5 + DAT_001801f0) = 0;
LAB_00043b2c:
          *(undefined8 *)(lVar5 + 8 + DAT_00180210) = *(undefined8 *)(lVar5 + 8 + DAT_001801c0);
          *(undefined8 *)(lVar5 + 8 + DAT_001801f0) = *(undefined8 *)(lVar5 + 8 + DAT_001801c0);
        }
        else {
          lVar1 = FUN_000014c8(lVar1);
          *(longlong *)(lVar5 + DAT_001801f0) = lVar1;
          if (*(longlong *)(lVar5 + DAT_001801f0) != 0) {
            plVar7 = (longlong *)(DAT_001801c0 + lVar5);
            lVar1 = *plVar7;
            if (lVar1 == 0) {
              lVar1 = FUN_000014c8(plVar7[1]);
              *(longlong *)(lVar5 + DAT_001801c0) = lVar1;
              plVar7 = (longlong *)(DAT_001801c0 + lVar5);
              lVar1 = *plVar7;
              if (lVar1 == 0) goto LAB_00043b5c;
            }
            (**(code **)(DAT_00180188 + 0x160))
                      (*(undefined8 *)(lVar5 + DAT_001801f0),lVar1,plVar7[1]);
            lVar1 = FUN_000014c8(*(undefined8 *)(lVar5 + 8 + DAT_001801c0));
            *(longlong *)(lVar5 + DAT_00180210) = lVar1;
            (**(code **)(DAT_00180188 + 0x160))
                      (lVar1,*(undefined8 *)(lVar5 + DAT_001801c0),
                       *(undefined8 *)(lVar5 + 8 + DAT_001801c0));
            goto LAB_00043b2c;
          }
        }
LAB_00043b5c:
        uVar6 = uVar6 + 1;
      } while (uVar6 < *DAT_001937f0);
    }
  }
  DAT_0010a760 = 2;
  FUN_000367c0(param_1);
  uVar4 = 1;
  DAT_0010a760 = 0;
  puVar3 = DAT_001937e8;
  if (1 < *DAT_001937e8) {
    do {
      uVar6 = (uint)uVar4;
      plVar7 = (longlong *)((ulonglong)puVar3[uVar4 + 1] + DAT_001938e0);
      if (((*plVar7 == param_1) || (*plVar7 == 0xffff)) && (*plVar7 != 0xffff)) {
        if (((*(byte *)((longlong)plVar7 + 0x14) & 0x20) != 0) &&
           (*(short *)((longlong)plVar7 + 0x12) == 0)) {
          *(ushort *)((longlong)plVar7 + 0x12) = DAT_0018f054;
        }
        FUN_00066ce8(uVar6,uVar6 + 1);
        FUN_00019744((longlong)plVar7,param_2);
        puVar3 = DAT_001937e8;
      }
      uVar4 = (ulonglong)(uVar6 + 1);
    } while (uVar6 + 1 < *puVar3);
  }
  if (DAT_00190b38 == '\x01') {
    uVar4 = 1;
    uVar2 = DAT_0018f054;
    if (1 < *puVar3) {
      do {
        if ((*(longlong *)((ulonglong)puVar3[uVar4 + 1] + DAT_001938e0) == DAT_00190b40) &&
           (*(short *)((longlong)((ulonglong)puVar3[uVar4 + 1] + DAT_001938e0) + 10) == DAT_00190b2c
           )) {
          uVar2 = (ushort)uVar4;
          break;
        }
        uVar6 = (int)uVar4 + 1;
        uVar4 = (ulonglong)uVar6;
      } while (uVar6 < *puVar3);
    }
    FUN_000680f0(uVar2);
    DAT_00190b38 = '\0';
  }
  return;
}

