
ulonglong FUN_00009e70(longlong param_1,int param_2,ulonglong param_3,ulonglong param_4,
                      undefined8 *param_5,char param_6)

{
  byte bVar1;
  ushort uVar2;
  int *piVar3;
  longlong lVar4;
  undefined2 *puVar5;
  uint uVar6;
  ulonglong uVar7;
  undefined8 *puVar8;
  uint uVar9;
  ulonglong uVar10;
  bool bVar11;
  ulonglong local_res18;
  undefined8 *local_48;
  longlong local_40;
  
  lVar4 = DAT_000104c0;
  puVar5 = DAT_00010460;
  uVar7 = 0;
  piVar3 = *(int **)(param_1 + 8);
  local_40 = 0;
  if (*piVar3 != param_2) {
    return 0x800000000000000d;
  }
  if (param_6 == '\x01') {
LAB_00009f1d:
    *(undefined1 *)((longlong)piVar3 + 5) = 1;
    (**(code **)(lVar4 + 0x168))(puVar5,0x1f);
    puVar5 = DAT_00010460;
    *DAT_00010460 = 0xa27;
    *(undefined1 *)((longlong)puVar5 + 3) = *(undefined1 *)(param_1 + 0x70);
    *(undefined1 *)(puVar5 + 2) = 0;
    FUN_00003d5c();
    puVar5 = DAT_00010460;
    lVar4 = *(longlong *)(param_1 + 0x68);
    if ((((*(byte *)(DAT_00010460 + 2) & 1) == 0) || (*(longlong *)(lVar4 + 0x60) == 0)) ||
       (*(short *)(lVar4 + 0x5e) == 0)) {
      *(undefined8 *)(*(longlong *)(param_1 + 8) + 0x18) = 0;
      if ((param_6 == '\x01') && ((*(byte *)(puVar5 + 2) & 2) != 0)) {
        return 0x800000000000000d;
      }
    }
    else {
      piVar3 = *(int **)(param_1 + 8);
      if ((((uint)*(ushort *)(lVar4 + 0x5e) != piVar3[3]) ||
          (*(longlong *)(lVar4 + 0x60) + -1 != *(longlong *)(piVar3 + 6))) ||
         ((*(byte *)(DAT_00010460 + 2) & 2) != 0)) {
        *piVar3 = *piVar3 + 1;
        *(undefined1 *)(*(longlong *)(param_1 + 8) + 7) = 0;
        *(longlong *)(*(longlong *)(param_1 + 8) + 0x18) = *(longlong *)(lVar4 + 0x60) + -1;
        *(uint *)(*(longlong *)(param_1 + 8) + 0xc) = (uint)*(ushort *)(lVar4 + 0x5e);
      }
    }
    if ((*(byte *)(puVar5 + 2) & 1) != 0) {
      piVar3 = *(int **)(param_1 + 8);
      uVar10 = *(ulonglong *)(piVar3 + 6);
      if ((uVar10 != 0) && (piVar3[3] != 0)) {
        if (param_2 != *piVar3) {
          return 0x800000000000000d;
        }
        if (param_6 == '\x01') {
          if (param_4 == 0) {
            return 0;
          }
          if ((param_5 == (undefined8 *)0x0) ||
             ((1 < (uint)piVar3[4] && ((ulonglong)param_5 % (ulonglong)(uint)piVar3[4] != 0))))
          goto LAB_00009ede;
          if ((**(byte **)(param_1 + 0x68) & 2) == 0) {
            return 0x8000000000000007;
          }
        }
        if ((param_3 <= uVar10) &&
           (uVar2 = *(ushort *)(*(longlong *)(param_1 + 0x68) + 0x5e),
           (param_3 - 1) + param_4 / uVar2 <= uVar10)) {
          if (param_4 % (ulonglong)uVar2 != 0) {
            return 0x8000000000000004;
          }
          local_48 = param_5;
          if (((ulonglong)param_5 & 0xffffffff00000000) != 0) {
            local_40 = (ulonglong)((param_4 & 0xfff) != 0) + (param_4 >> 0xc);
            local_48 = (undefined8 *)0xffffffff;
            uVar7 = (**(code **)(DAT_000104c0 + 0x28))(1);
            if ((longlong)uVar7 < 0) {
              local_48 = param_5;
            }
            else if (((param_6 == '\0') && (param_4 != 0)) && (param_5 != (undefined8 *)0xffffffff))
            {
              FUN_00000280((undefined8 *)0xffffffff,param_5,param_4);
            }
          }
          uVar10 = param_4 & 0xffffffff;
          if ((int)param_4 != 0) {
            puVar8 = local_48;
            local_res18 = param_3;
            do {
              uVar9 = (uint)uVar10;
              uVar6 = uVar9;
              if (0x10000 < uVar9) {
                uVar6 = 0x10000;
              }
              (**(code **)(DAT_000104c0 + 0x168))(DAT_00010460);
              puVar5 = DAT_00010460;
              *(char *)((longlong)DAT_00010460 + 1) = (param_6 != '\x01') + '\f';
              uVar7 = 0;
              *(undefined1 *)puVar5 = 0x27;
              *(undefined1 *)((longlong)puVar5 + 3) = *(undefined1 *)(param_1 + 0x70);
              *(ulonglong *)(puVar5 + 4) = local_res18;
              uVar2 = *(ushort *)(*(longlong *)(param_1 + 0x68) + 0x5e);
              *(undefined4 *)(puVar5 + 9) = 0;
              puVar5[8] = (short)(uVar6 / uVar2);
              *(undefined8 **)(puVar5 + 0xb) = puVar8;
              FUN_00003d5c();
              bVar1 = *(byte *)(DAT_00010460 + 1);
              if (bVar1 < 0x12) {
                if ((bVar1 < 0x10) && (bVar1 != 2)) {
                  if (bVar1 != 3) {
                    if ((bVar1 != 4) && (bVar1 != 7)) {
                      bVar11 = bVar1 == 10;
                      goto LAB_0000a20f;
                    }
                    goto LAB_0000a211;
                  }
                  uVar7 = -(ulonglong)(param_6 != '\x01') & 0x8000000000000008;
                  if (param_6 != '\x01') {
                    *(undefined1 *)(*(longlong *)(param_1 + 8) + 7) = 1;
                  }
                }
                else {
LAB_0000a211:
                  uVar7 = 0x8000000000000007;
                }
                if ((longlong)uVar7 < 0) break;
              }
              else {
                if (bVar1 == 0x20) goto LAB_0000a211;
                if (bVar1 == 0x31) {
                  uVar7 = 0x800000000000000c;
                  *(undefined1 *)(*(longlong *)(param_1 + 8) + 5) = 0;
                  break;
                }
                if (bVar1 == 0x80) goto LAB_0000a211;
                bVar11 = bVar1 == 0xaa;
LAB_0000a20f:
                if (bVar11) goto LAB_0000a211;
              }
              uVar10 = (ulonglong)(uVar9 - uVar6);
              puVar8 = (undefined8 *)((longlong)puVar8 + (ulonglong)uVar6);
              local_res18 = local_res18 +
                            (ulonglong)uVar6 /
                            (ulonglong)*(ushort *)(*(longlong *)(param_1 + 0x68) + 0x5e);
            } while (uVar9 - uVar6 != 0);
          }
          if (local_48 != param_5) {
            if ((param_6 == '\x01') && (param_4 - uVar10 != 0)) {
              FUN_00000280(param_5,local_48,param_4 - uVar10);
            }
            (**(code **)(DAT_000104c0 + 0x30))(local_48,local_40);
            return uVar7;
          }
          return uVar7;
        }
        goto LAB_00009ede;
      }
    }
    *(undefined1 *)(*(longlong *)(param_1 + 8) + 5) = 0;
    *(undefined8 *)(*(longlong *)(param_1 + 8) + 0x18) = 0;
    uVar7 = 0x800000000000000c;
  }
  else {
    if (param_4 == 0) {
      return 0;
    }
    if ((param_5 != (undefined8 *)0x0) &&
       (((uint)piVar3[4] < 2 || ((ulonglong)param_5 % (ulonglong)(uint)piVar3[4] == 0)))) {
      if ((**(byte **)(param_1 + 0x68) & 2) == 0) {
        return 0x8000000000000007;
      }
      goto LAB_00009f1d;
    }
LAB_00009ede:
    uVar7 = 0x8000000000000002;
  }
  return uVar7;
}

