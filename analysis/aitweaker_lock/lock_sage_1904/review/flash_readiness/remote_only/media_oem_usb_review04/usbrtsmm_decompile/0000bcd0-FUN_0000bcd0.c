
uint FUN_0000bcd0(longlong param_1,longlong param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined8 *puVar5;
  ulonglong uVar6;
  undefined8 *puVar7;
  ushort uVar8;
  uint uVar9;
  undefined8 *puVar10;
  uint uVar11;
  
  if (*(int *)(param_2 + 0x12) == 0) {
    uVar2 = 0;
  }
  else {
    uVar1 = DAT_00029600[0x1b0];
    if (*(short *)((longlong)DAT_00029600 + 0x6ae) != 0) {
      *(short *)(DAT_00029600 + 0x1b0) = *(short *)((longlong)DAT_00029600 + 0x6ae);
    }
    if ((*(short *)(param_2 + 0x16) == 0) && (*(short *)(param_2 + 0x18) == 0)) {
      if (((*DAT_00029600 & 0x1000000) == 0) &&
         ((*(uint *)((longlong)DAT_00029600 + 0x921) & 0x400) == 0)) {
        uVar2 = FUN_0000cef0(param_1,*(undefined1 *)(param_2 + 9),*(undefined8 *)(param_2 + 10),
                             *(undefined4 *)(param_2 + 0x12));
      }
      else {
        puVar10 = *(undefined8 **)(param_2 + 10);
        puVar5 = puVar10;
        if ((puVar10 < (undefined8 *)0x100000) &&
           (((puVar5 = *(undefined8 **)(DAT_0001e800 + 0x6a), *(char *)(param_2 + 9) != -0x80 &&
             ((ulonglong)*(uint *)(param_2 + 0x12) != 0)) && (puVar5 != puVar10)))) {
          FUN_00001000(puVar5,puVar10,(ulonglong)*(uint *)(param_2 + 0x12));
        }
        uVar2 = FUN_0000cef0(param_1,*(undefined1 *)(param_2 + 9),puVar5,
                             *(undefined4 *)(param_2 + 0x12));
        if (((uVar2 != 0) &&
            (puVar10 = *(undefined8 **)(param_2 + 10), puVar10 < (undefined8 *)0x100000)) &&
           (*(char *)(param_2 + 9) == -0x80)) {
          if (((ulonglong)*(uint *)(param_2 + 0x12) != 0) &&
             (puVar10 != *(undefined8 **)(DAT_0001e800 + 0x6a))) {
            FUN_00001000(puVar10,*(undefined8 **)(DAT_0001e800 + 0x6a),
                         (ulonglong)*(uint *)(param_2 + 0x12));
          }
        }
      }
    }
    else {
      puVar5 = (undefined8 *)
               FUN_00004150((ushort)((ulonglong)*(ushort *)(param_1 + 0x5e) + 0x1f >> 5));
      uVar9 = *(uint *)(param_2 + 0x12);
      uVar2 = 0;
      uVar8 = *(ushort *)(param_2 + 0x16);
      puVar10 = *(undefined8 **)(param_2 + 10);
      uVar11 = (uVar9 - *(ushort *)(param_2 + 0x18)) - (uint)uVar8;
      if (uVar9 != 0) {
        do {
          if (*(ushort *)(param_1 + 0x5e) <= uVar9) {
            uVar9 = (uint)*(ushort *)(param_1 + 0x5e);
          }
          iVar3 = FUN_0000cef0(param_1,*(undefined1 *)(param_2 + 9),puVar5,uVar9);
          if (iVar3 == 0) {
            uVar2 = 0;
            break;
          }
          uVar2 = uVar2 + uVar9;
          if (uVar11 != 0) {
            puVar7 = puVar5;
            if (uVar8 != 0) {
              uVar4 = (uint)uVar8;
              if (uVar9 <= uVar4) {
                uVar8 = uVar8 - (short)uVar9;
                goto LAB_0000beae;
              }
              uVar6 = (ulonglong)uVar8;
              uVar8 = 0;
              puVar7 = (undefined8 *)(uVar6 + (longlong)puVar5);
              uVar9 = uVar9 - uVar4;
            }
            if (uVar11 < uVar9) {
              uVar9 = uVar11;
            }
            if ((uVar9 != 0) && (puVar10 != puVar7)) {
              FUN_00001000(puVar10,puVar7,(ulonglong)uVar9);
            }
            puVar10 = (undefined8 *)((longlong)puVar10 + (ulonglong)uVar9);
            uVar11 = uVar11 - uVar9;
          }
LAB_0000beae:
          uVar9 = *(uint *)(param_2 + 0x12);
        } while (uVar2 < uVar9);
      }
      FUN_00004324(puVar5,(ushort)((ulonglong)*(ushort *)(param_1 + 0x5e) + 0x1f >> 5));
    }
    *(short *)(DAT_00029600 + 0x1b0) = (short)uVar1;
    *(undefined2 *)((longlong)DAT_00029600 + 0x6ae) = 0;
  }
  return uVar2;
}

