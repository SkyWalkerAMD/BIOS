
longlong Observed_FrameAddControl(longlong param_1,longlong param_2)

{
  bool bVar1;
  byte bVar2;
  int iVar3;
  undefined8 *puVar4;
  short sVar5;
  ushort uVar6;
  ushort uVar7;
  ushort uVar8;
  ulonglong uVar9;
  longlong lVar10;
  longlong *plVar11;
  ushort uVar12;
  longlong lVar13;
  
  uVar8 = *(ushort *)(param_1 + 0x3c);
  uVar9 = (ulonglong)uVar8;
  uVar12 = 0;
  lVar10 = -0x7ffffffffffffffd;
  bVar1 = false;
  puVar4 = FUN_0000fc40(*(longlong *)(param_1 + 0x48),uVar9 * 8,uVar9 * 8 + 8);
  if (puVar4 == (undefined8 *)0x0) {
    lVar10 = -0x7ffffffffffffff7;
  }
  else {
    *(undefined8 **)(param_1 + 0x48) = puVar4;
    plVar11 = puVar4 + uVar9;
    lVar13 = 0;
    sVar5 = DAT_000943f0;
    if (DAT_000943f0 != 0) {
      do {
        if (sVar5 == *(short *)(param_2 + 0x14)) {
          lVar10 = (*(code *)**(undefined8 **)((longlong)&PTR_PTR_000943f8 + lVar13))(plVar11);
          if ((-1 < lVar10) && ((&DAT_00094400)[lVar13] != '\0')) {
            (**(code **)(*(longlong *)((longlong)&PTR_PTR_000943f8 + lVar13) + 0x28))
                      (*plVar11,param_1,*(undefined8 *)((longlong)&PTR_FUN_00094408 + lVar13),
                       *(undefined8 *)((longlong)&PTR_DAT_00094410 + lVar13));
          }
          bVar1 = true;
        }
        uVar12 = uVar12 + 1;
        lVar13 = (ulonglong)uVar12 * 0x28;
        sVar5 = (&DAT_000943f0)[(ulonglong)uVar12 * 0x14];
      } while ((&DAT_000943f0)[(ulonglong)uVar12 * 0x14] != 0);
      if (bVar1) {
        if (lVar10 < 0) {
          return lVar10;
        }
        lVar10 = (**(code **)(*(longlong *)*plVar11 + 0x10))((longlong *)*plVar11,param_2);
        if (lVar10 < 0) {
          return lVar10;
        }
        sVar5 = *(short *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x20) != 4) {
          sVar5 = (sVar5 - (ushort)DAT_00093cd0) + -2;
        }
        (**(code **)(*(longlong *)*plVar11 + 0x40))((longlong *)*plVar11,sVar5,1);
        bVar2 = DAT_00093cd0;
        uVar8 = uVar8 + 1;
        *(undefined4 *)(*plVar11 + 0x6c) = *(undefined4 *)(param_1 + 0x20);
        *(int *)(param_1 + 0x3c) = *(int *)(param_1 + 0x3c) + 1;
        (**(code **)(*(longlong *)*plVar11 + 0x38))
                  ((longlong *)*plVar11,(ushort)bVar2 + *(short *)(param_1 + 0x2e),
                   uVar8 + *(short *)(param_1 + 0x2c) + -1);
        uVar12 = 0;
        *(undefined1 *)(param_1 + 0x58) = 0;
        if (*(short *)(param_1 + 0x3c) != 0) {
          iVar3 = 0;
          if (*(char *)(param_1 + 0x25) == '\x01') {
            iVar3 = 2;
          }
          uVar6 = uVar12;
          do {
            uVar7 = *(ushort *)
                     (*(longlong *)(*(longlong *)(param_1 + 0x48) + (ulonglong)uVar6 * 8) + 0x66);
            if ((int)((uint)*(ushort *)(param_1 + 0x2a) - iVar3) < (int)((uint)uVar12 + (uint)uVar7)
               ) goto LAB_0002236f;
            uVar12 = uVar12 + uVar7;
            uVar7 = uVar6 + 1;
            *(uint *)(param_1 + 0x60) = (uint)uVar6;
            uVar6 = uVar7;
          } while (uVar7 < *(ushort *)(param_1 + 0x3c));
        }
        *(int *)(param_1 + 0x60) = *(int *)(param_1 + 0x3c) + -1;
LAB_0002236f:
        puVar4 = FUN_0000fc40(*(longlong *)(param_1 + 0x68),(ulonglong)uVar8 * 4 - 4,
                              (ulonglong)uVar8 * 4);
        if (puVar4 == (undefined8 *)0x0) {
          return lVar10;
        }
        *(undefined2 *)((longlong)puVar4 + (ulonglong)uVar8 * 4 + -2) =
             *(undefined2 *)(*plVar11 + 0x60);
        *(undefined2 *)((longlong)puVar4 + (ulonglong)uVar8 * 4 + -4) =
             *(undefined2 *)(*plVar11 + 0x62);
        *(undefined8 **)(param_1 + 0x68) = puVar4;
        return lVar10;
      }
    }
    if (*(short *)(param_2 + 0x14) == 0) {
      *(int *)(param_1 + 0x40) = *(int *)(param_1 + 0x40) + 1;
    }
  }
  return lVar10;
}

